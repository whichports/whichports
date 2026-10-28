"""Reach the control plane's join engine from the site renderer.

`controlplane/app/join.py` compares the three views per port and per address
family and produces the five states. This renderer has to show them and cannot
simply import it, so this module is the one place that knows how.

## Why a plain import is not only impossible but actively fatal

Both trees have a package called `app`. `site/app` has no `__init__.py`, so it
is a namespace package. `controlplane/app` has one, so it is a regular package.
**A regular package wins over a namespace portion whatever the order of
`sys.path`**, so putting the control plane on the path does not add `app.join`
to what `app` already holds, it replaces `app` entirely. `import app.build`
then raises `ModuleNotFoundError` and the renderer dies on every timer tick,
which is the six minute frozen page of `docs/RECORD.md` 4.37 with a different
cause. There is no ordering of the two that yields both.

So the package is loaded under a **different name**, `cpapp`. `join.py`'s own
`from . import hetzner, prober` then resolves inside `cpapp` and `app` is never
touched.

## Two layouts, because the box is not the repository

In this checkout the two trees sit side by side, `controlplane/app` and
`site/app`. `ops/deploy-controlplane.sh` copies them into one directory, so on
the production box they are `/srv/controlplane/app` and
`/srv/controlplane/site/app`. Both are tried, the box's first, and the one that
holds a `join.py` wins.

## It raises rather than degrading, on purpose

A renderer that quietly falls back to "not tested" when it cannot load the
engine is a monitoring tool failing silently, which is the thing
`docs/PRODUCT.md` 4c exists to prevent. `ops/deploy-controlplane.sh` runs this
renderer once against the real database before it reports success, so a broken
load stops a deploy rather than freezing a page.
"""
import importlib.util
import pathlib
import sys

# Not `app`, and the whole module is about why. Anything but the name the site
# tree already uses.
ALIAS = "cpapp"


class JoinEngineMissing(RuntimeError):
    """The control plane's package is not beside this one."""


def candidate_directories(here=None):
    """Where the control plane's `app` package could be, box first.

    `here` is `site/app`. Its parent is `site`, and its grandparent is either
    `/srv/controlplane` on the box or the repository root in a checkout.
    """
    here = pathlib.Path(here or __file__).resolve().parent
    root = here.parent.parent
    return [root / "app", root / "controlplane" / "app"]


def module(name, here=None):
    """One module from the control plane's package, by name.

    `load()` is this with `"join"`, kept as its own name because it is what
    almost every caller wants and because the docstring above is about it. The
    renderer also needs `channels`, and a second loader beside this one would
    be a second place to get the `app` collision wrong.
    """
    load(here)
    return importlib.import_module(f"{ALIAS}.{name}")


def load(here=None):
    """The control plane's `join` module, loaded under `ALIAS`.

    Loaded once and then handed back from `sys.modules`, because the renderer
    calls this per host and re-executing a 1,700 line module each time would be
    a cost for nothing.
    """
    # The cache is the production path and only the production path. A caller
    # that names a directory is asking about that directory, and handing back
    # whatever was loaded first would answer a different question, which is how
    # a test can pass alone and fail in a suite.
    loaded = sys.modules.get(ALIAS + ".join")
    if here is None and loaded is not None:
        return loaded

    for directory in candidate_directories(here):
        init = directory / "__init__.py"
        if not (directory / "join.py").is_file() or not init.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            ALIAS, init, submodule_search_locations=[str(directory)])
        package = importlib.util.module_from_spec(spec)
        # Registered before it is executed, which is what a package import
        # needs: `join.py` says `from . import prober` and the machinery
        # resolves that through `sys.modules[ALIAS]`.
        sys.modules[ALIAS] = package
        spec.loader.exec_module(package)
        return importlib.import_module(ALIAS + ".join")

    raise JoinEngineMissing(
        "the control plane's app package is not beside this renderer. Looked in "
        + ", ".join(str(d) for d in candidate_directories(here))
        + ". On the box ops/deploy-controlplane.sh puts it in the first of"
          " those, and in a checkout it is the second")
