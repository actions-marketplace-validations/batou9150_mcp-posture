"""mkdocs-gen-files hook: one page per check, generated from the code registry."""

import mkdocs_gen_files

from mcp_posture.docs import check_page, index_page
from mcp_posture.registry import catalogue

metas = catalogue()
with mkdocs_gen_files.open("checks/index.md", "w") as f:
    f.write(index_page(metas))
for meta in metas:
    with mkdocs_gen_files.open(f"checks/{meta.docs_slug}.md", "w") as f:
        f.write(check_page(meta))
