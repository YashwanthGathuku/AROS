# Adding a research skill

1. Add an object matching `skills/schema/research-skill.schema.json`.
2. Put it in `python/aros_research/skills/catalog.py`.
3. Run `python scripts/render_skills.py` to emit JSON + markdown.
4. Skills propose experiments. They do not authorize.
