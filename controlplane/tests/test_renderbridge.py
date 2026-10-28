"""The bridge that lets this package call the site's renderer.

    python -m pytest tests/test_renderbridge.py

Both trees have a package called `app` and only one can hold the name in one
interpreter (`app/renderbridge.py` and `site/app/joinbridge.py` are the two
halves of that story). These tests are the proof the bridge keeps the names
apart: after a load, `app` is still this package, no `app.*` name was added
or replaced, and the renderer runs and answers with what is in the database.
"""

import importlib.util
import pathlib
import sys
import types

import pytest

from app import accounts, db, renderbridge, store


def seeded_db(tmp_path, monkeypatch, hosts=("almabox",)):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    accounts.init(con)
    for name in hosts:
        store.add_host(con, name, workspace_id=1)
    con.close()
    return db.db_path()


# ==================================== the collision proof

def test_loading_the_bridge_does_not_touch_this_package():
    """The heart of it. `import app.build` from the renderer would have had to
    resolve through this package, which has no `build`, and any arrangement
    that made the site's `app` win would have taken this package's name away.
    So: load the bridge, then check `app` is still this exact package, its
    module list gained nothing, lost nothing, and had nothing replaced."""
    before = {name: sys.modules[name] for name in list(sys.modules)
              if name == "app" or name.startswith("app.")}
    module = renderbridge.load()
    after = {name: sys.modules[name] for name in list(sys.modules)
             if name == "app" or name.startswith("app.")}
    assert after == before
    # Identity, not equality: the same module objects, not lookalikes.
    for name in before:
        assert after[name] is before[name], name
    # And `app` still resolves to this package by file, not by luck.
    assert pathlib.Path(sys.modules["app"].__file__).parent \
        == pathlib.Path(renderbridge.__file__).parent
    # The renderer lives under the alias, never under `app`.
    assert module.__name__ == renderbridge.ALIAS + ".render_live"
    assert "render_live" not in {n.rsplit(".", 1)[-1] for n in before}


def test_this_package_never_grows_the_names_the_site_tree_uses():
    """The bridge relies on `app.build`, `app.packetpath` and `app.joinbridge`
    not existing in this package: if one ever appears, the renderer's script
    mode and this package would be two owners of one name and the failure
    would be wherever imports happened to win. Refuse the collision here, by
    name, the day the file lands."""
    here = pathlib.Path(renderbridge.__file__).parent
    for name in ("build", "packetpath", "joinbridge", "render_live", "theme"):
        assert not (here / f"{name}.py").exists(), (
            f"controlplane/app/{name}.py collides with the site tree's"
            f" {name}; one of them must be renamed")


def test_the_theme_name_is_claimed_or_refused_never_shadowed(monkeypatch):
    """`theme` is the one top-level name the renderer imports. The bridge may
    only register it when nothing else is or could be `theme`, so a foreign
    module already holding the name is a loud refusal rather than a dashboard
    styled by whatever that module happens to hold."""
    imposter = types.ModuleType("theme")
    imposter.__file__ = "/somewhere/else/theme.py"
    monkeypatch.setitem(sys.modules, "theme", imposter)
    with pytest.raises(renderbridge.NameCollision):
        renderbridge._claim_theme(
            renderbridge._site_directory() / "theme.py")


def test_the_venv_offers_no_module_named_theme():
    """The refusal above also fires when an installed package could provide
    `theme`. Prove the environment this suite runs in has none, so the claim
    path is the one production takes. If this ever fails, a dependency brought
    a `theme` module and the bridge's name needs deciding, not working around."""
    if "theme" in sys.modules:
        # Already claimed by an earlier test's load, which is the claim path
        # working. What must hold is that it is the site's file.
        claimed = sys.modules["theme"].__file__
        assert claimed == str(renderbridge._site_directory() / "theme.py")
    else:
        assert importlib.util.find_spec("theme") is None


def test_an_alias_already_taken_by_something_else_is_refused(monkeypatch):
    imposter = types.ModuleType(renderbridge.ALIAS)
    monkeypatch.setitem(sys.modules, renderbridge.ALIAS, imposter)
    monkeypatch.delitem(sys.modules, renderbridge.ALIAS + ".render_live",
                        raising=False)
    with pytest.raises(renderbridge.NameCollision):
        renderbridge.load(here=pathlib.Path(renderbridge.__file__).parent)


# ==================================== loading

def test_the_second_load_is_the_first_one_cached():
    assert renderbridge.load() is renderbridge.load()


def test_a_missing_site_tree_raises_rather_than_degrading(tmp_path):
    """A dashboard that cannot load its renderer must say so, not serve
    nothing. The deploy runs a render before reporting success for exactly
    this reason."""
    with pytest.raises(renderbridge.RendererMissing):
        renderbridge._site_directory(here=tmp_path)


def test_the_candidate_directories_are_box_first():
    here = pathlib.Path(renderbridge.__file__).parent
    box, checkout = renderbridge.candidate_directories()
    assert box == here.parent / "site"
    assert checkout == here.parent.parent / "site"


# ==================================== the render itself

def test_the_renderer_renders_this_database(tmp_path, monkeypatch):
    """End to end through the bridge: the page for workspace 1 names the host
    that is in the database and carries the page shell."""
    path = seeded_db(tmp_path, monkeypatch, hosts=("bridge-proof",))
    html = renderbridge.load().render(path, workspace_id=1)
    assert "bridge-proof" in html
    assert "<!doctype html>" in html.lower()


def test_the_join_engine_reached_through_the_bridge_is_a_second_copy():
    """`siteapp.joinbridge` loads this package again under `cpapp` rather than
    reusing the imported `app`, on purpose: two clean copies over one set of
    modules owned by two loaders. Pin that it is a copy from the same files,
    so a future 'optimisation' that starts sharing module objects across the
    loaders shows up here as the decision it would be."""
    renderbridge.load()
    cpapp_join = sys.modules["cpapp.join"]
    import app.join
    assert cpapp_join is not app.join
    assert pathlib.Path(cpapp_join.__file__) == pathlib.Path(app.join.__file__)
