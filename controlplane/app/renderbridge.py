"""Reach the site's dashboard renderer from the control plane.

`site/app/render_live.py` builds one workspace's whole page from the database.
The ingest has to call it on every dashboard request and cannot simply import
it, so this module is the one place that knows how. It is the mirror of
`site/app/joinbridge.py`, which reaches this package from the site tree, and
that file's docstring is the long version of the problem.

## Why a plain import is not only impossible but actively fatal

Both trees have a package called `app`. In this process `app` is already the
control plane's package, a regular one with an `__init__.py`, and **a regular
package wins over a namespace portion whatever the order of `sys.path`**. So
putting `site/` on the path does not make `import app.build` reach the site's
template, it keeps resolving into this package, which has no `build`, and the
import dies. Worse, any path arrangement that made the site's `app` win would
take this package's own name away from the ingest that is importing it.

So the site package is loaded under a **different name**, `siteapp`, exactly
the way joinbridge loads this package under `cpapp`. The renderer's own
imports are relative when it is loaded as part of a package (`render_live.py`
says why beside them), so they resolve inside `siteapp` and `app` is never
touched.

## `theme` is the one name that is not relative

`site/theme.py` sits beside `site/app`, not inside it, and the renderer and
the template both say `import theme`. So it is loaded here first, from its
file, and registered in `sys.modules` under that name, after checking the
name is free: if anything else in this interpreter already is or could be
`theme`, this refuses loudly rather than shadow it or be shadowed by it.
`app/web_pages.py` loads the same file under `whichports_theme` for the login
page; that stays its own copy on purpose, because sharing it would couple the
login page's loader to this one's collision rules.

## The join engine is loaded twice, and that is accepted

The renderer reaches the five-state join through `siteapp.joinbridge`, which
loads this same package a second time under `cpapp`, from the same files.
Making it reuse the already-imported `app` would mean handing modules across
two loaders that disagree about names, which is how half-shared state starts.
Two clean copies cost a few megabytes once and share nothing but the database
file, which both open read-only for the render.

## It raises rather than degrading, on purpose

A dashboard that quietly serves nothing because the renderer could not load
is a monitoring tool failing silently. `ops/deploy-controlplane.sh` renders
every workspace through this module against the real database before it
reports success, so a broken load stops a deploy rather than a customer.
"""
import argparse
import importlib
import importlib.machinery
import importlib.util
import pathlib
import sys
import threading

# Not `app`, and the module docstring is about why. Anything but the name this
# package already carries.
ALIAS = "siteapp"

# The name the renderer imports the design system by. Owned by `site/theme.py`
# and registered by `load()` below.
THEME = "theme"

# The first dashboard requests arrive on FastAPI's worker threads, several at
# once, and this module edits `sys.modules` by hand, which the import system's
# own per-module locks do not cover. One lock around the whole load keeps a
# half-executed module from ever being what another thread finds.
_lock = threading.Lock()


class RendererMissing(RuntimeError):
    """The site's renderer is not beside this package."""


class NameCollision(RuntimeError):
    """A name this bridge needs is already taken by something else."""


def candidate_directories(here=None):
    """Where `site/` could be, box first.

    `here` is `controlplane/app`. Its parent is `/srv/controlplane` on the box,
    where the deploy puts the site tree at `site/`, and `controlplane` in a
    checkout, where the site tree is the repository root's `site/`.
    """
    here = pathlib.Path(here or __file__).resolve().parent
    return [here.parent / "site", here.parent.parent / "site"]


def _site_directory(here=None):
    for directory in candidate_directories(here):
        if (directory / "app" / "render_live.py").is_file() \
                and (directory / "theme.py").is_file():
            return directory
    raise RendererMissing(
        "the site's renderer is not beside this package. Looked in "
        + ", ".join(str(d) for d in candidate_directories(here))
        + ". On the box ops/deploy-controlplane.sh puts it in the first of"
          " those, and in a checkout it is the second")


def _claim_theme(theme_path):
    """`site/theme.py`, loaded and registered as `theme`, or NameCollision.

    The check runs before anything is registered. A `theme` that is already
    loaded from some other file, or that any installed package could provide,
    means the name is not ours, and serving a dashboard styled by whatever
    that module happens to hold is worse than refusing.
    """
    loaded = sys.modules.get(THEME)
    if loaded is not None:
        if getattr(loaded, "__file__", None) == str(theme_path):
            return loaded
        raise NameCollision(
            f"a module named {THEME!r} is already loaded from "
            f"{getattr(loaded, '__file__', 'nowhere')} and it is not "
            f"{theme_path}, so the renderer cannot be loaded in this process")
    elsewhere = importlib.util.find_spec(THEME)
    if elsewhere is not None:
        raise NameCollision(
            f"something else on sys.path already provides a module named "
            f"{THEME!r} ({elsewhere.origin}), and registering "
            f"{theme_path} over it would shadow an installed package")
    spec = importlib.util.spec_from_file_location(THEME, theme_path)
    module = importlib.util.module_from_spec(spec)
    # Registered before it is executed, the shape every package import takes.
    # theme.py imports only the standard library, so nothing here recurses.
    sys.modules[THEME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # A half-executed module must not be what the next caller finds.
        sys.modules.pop(THEME, None)
        raise
    return module


def load(here=None):
    """The site's `render_live` module, loaded under `ALIAS`, once.

    Everything a render will import is loaded in here, under the lock: the
    theme, the template, and the join engine's modules through the renderer's
    own joinbridge. After the first call every per-request use is a
    `sys.modules` lookup, so no request thread ever runs this function's
    surgery concurrently with another.
    """
    loaded = sys.modules.get(ALIAS + ".render_live")
    if here is None and loaded is not None:
        return loaded
    with _lock:
        loaded = sys.modules.get(ALIAS + ".render_live")
        if here is None and loaded is not None:
            return loaded
        site = _site_directory(here)
        existing = sys.modules.get(ALIAS)
        if existing is not None and getattr(existing, "__path__", None) != \
                [str(site / "app")]:
            raise NameCollision(
                f"a module named {ALIAS!r} is already loaded and it is not "
                f"{site / 'app'}")
        _claim_theme(site / "theme.py")
        # An empty package whose search path is site/app. There is no
        # __init__.py there to execute, which is exactly the namespace-package
        # situation, so the package object is built rather than loaded and the
        # submodules are found through its __path__.
        spec = importlib.machinery.ModuleSpec(ALIAS, None, is_package=True)
        spec.submodule_search_locations = [str(site / "app")]
        sys.modules[ALIAS] = importlib.util.module_from_spec(spec)
        try:
            module = importlib.import_module(ALIAS + ".render_live")
            # The renderer only asks its joinbridge for these when a render
            # reaches them, which would be on a request thread, outside this
            # lock. Asked for here instead, so the by-hand loading is done
            # exactly once and everything later is a cache hit.
            module.joinbridge.load()
            for name in ("finding_alerts", "channels", "alerts"):
                module.joinbridge.module(name)
        except BaseException:
            for name in list(sys.modules):
                if name == ALIAS or name.startswith(ALIAS + "."):
                    del sys.modules[name]
            raise
        return module


def main():
    """Render every workspace once and say how big each page came out.

    This is what `ops/deploy-controlplane.sh` runs on the box before it
    reports success: it proves the exact load the ingest performs per request,
    bridge included, against the real database, writing nothing.
    """
    ap = argparse.ArgumentParser(description=main.__doc__, allow_abbrev=False)
    ap.add_argument("--db", required=True)
    args = ap.parse_args()
    render_live = load()
    for workspace_id in render_live.workspace_ids(args.db):
        html = render_live.render(args.db, workspace_id=workspace_id)
        print(f"workspace {workspace_id}: {len(html)} bytes")


if __name__ == "__main__":
    main()
