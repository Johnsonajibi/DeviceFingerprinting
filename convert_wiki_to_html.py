#!/usr/bin/env python3
"""Convert wiki Markdown files into polished HTML pages."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from markdown import Markdown
except ImportError as exc:  # pragma: no cover - executed when dependency missing
    message = (
        "Missing dependency: markdown. " "Install it with 'pip install markdown' before rerunning."
    )
    raise SystemExit(message) from exc


@dataclass(frozen=True)
class DocPage:
    """A single documentation page with metadata for navigation."""

    md_path: Path
    html_name: str
    title: str


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} | Device Fingerprinting Docs</title>
    <style>
        :root {{
            --slate-900: #0f172a;
            --slate-800: #1e293b;
            --slate-700: #334155;
            --slate-600: #475569;
            --slate-200: #e2e8f0;
            --slate-100: #f1f5f9;
            --brand: #2563eb;
            --brand-dark: #1e40af;
            --brand-soft: rgba(37, 99, 235, 0.12);
            --radius-md: 12px;
            --radius-sm: 8px;
            --shadow-lg: 0 24px 60px rgba(15, 23, 42, 0.18);
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a, #111827);
            color: var(--slate-900);
        }}

        .page {{
            display: grid;
            grid-template-columns: 300px minmax(0, 1fr);
            min-height: 100vh;
        }}

        .sidebar {{
            position: sticky;
            top: 0;
            align-self: start;
            min-height: 100vh;
            padding: 32px 28px;
            background: linear-gradient(160deg, rgba(30, 64, 175, 0.95), rgba(8, 47, 73, 0.95));
            color: #f8fafc;
            box-shadow: inset -1px 0 0 rgba(148, 163, 184, 0.12);
        }}

        .brand {{
            font-size: 1.35rem;
            font-weight: 600;
            line-height: 1.4;
            margin-bottom: 28px;
        }}

        .brand a {{
            color: inherit;
            text-decoration: none;
        }}

        .nav-title {{
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 0.12em;
            margin-bottom: 18px;
            color: rgba(226, 232, 240, 0.7);
        }}

        .nav-list {{
            list-style: none;
            padding: 0;
            margin: 0;
            display: grid;
            gap: 6px;
        }}

        .nav-item a {{
            display: block;
            padding: 10px 12px;
            border-radius: var(--radius-sm);
            color: rgba(248, 250, 252, 0.88);
            text-decoration: none;
            font-size: 0.95rem;
            transition: background 0.2s ease, color 0.2s ease;
        }}

        .nav-item a:hover {{
            background: rgba(148, 163, 184, 0.18);
            color: #fff;
        }}

        .nav-item.active a {{
            background: rgba(37, 99, 235, 0.95);
            color: #fff;
            box-shadow: 0 10px 25px rgba(37, 99, 235, 0.35);
        }}

        .content {{
            padding: 56px 72px;
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.02), rgba(15, 23, 42, 0.06));
        }}

        .content-inner {{
            max-width: 960px;
            margin: 0 auto;
            background: #fff;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            padding: 56px 56px 40px;
        }}

        .page-header {{
            margin-bottom: 36px;
            border-bottom: 1px solid var(--slate-200);
            padding-bottom: 24px;
        }}

        .page-header h1 {{
            font-size: 2.2rem;
            margin: 0 0 12px;
            color: var(--slate-900);
        }}

        .page-meta {{
            font-size: 0.9rem;
            color: var(--slate-600);
        }}

        .doc-toc {{
            background: var(--slate-100);
            border-radius: var(--radius-md);
            padding: 24px 24px 16px;
            margin-bottom: 32px;
            border: 1px solid rgba(148, 163, 184, 0.3);
        }}

        .doc-toc strong {{
            display: block;
            font-size: 0.95rem;
            margin-bottom: 12px;
            color: var(--slate-700);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .doc-toc ul {{
            margin: 0;
            padding-left: 20px;
            color: var(--slate-700);
        }}

        .doc-toc li {{
            margin-bottom: 6px;
        }}

        article {{
            color: var(--slate-800);
            font-size: 1rem;
            line-height: 1.75;
        }}

        article h2 {{
            margin-top: 40px;
            margin-bottom: 16px;
            font-size: 1.55rem;
            color: var(--slate-900);
        }}

        article h3 {{
            margin-top: 28px;
            margin-bottom: 12px;
            font-size: 1.25rem;
            color: var(--slate-800);
        }}

        article h4 {{
            margin-top: 24px;
            margin-bottom: 10px;
            font-size: 1.05rem;
            color: var(--slate-700);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        article p {{
            margin: 0 0 16px;
        }}

        article code {{
            background: rgba(37, 99, 235, 0.08);
            color: var(--brand-dark);
            padding: 2px 6px;
            border-radius: 6px;
            font-size: 0.92rem;
        }}

        pre {{
            background: #0f172a;
            color: #f8fafc;
            padding: 20px 24px;
            border-radius: var(--radius-sm);
            overflow-x: auto;
            font-size: 0.95rem;
            line-height: 1.6;
            margin: 24px 0;
        }}

        pre code {{
            background: none;
            padding: 0;
            color: inherit;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 28px 0;
            border: 1px solid rgba(148, 163, 184, 0.4);
            border-radius: var(--radius-sm);
            overflow: hidden;
        }}

        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid rgba(148, 163, 184, 0.28);
        }}

        th {{
            background: var(--brand);
            color: #fff;
            font-weight: 600;
            border-bottom: none;
        }}

        tr:nth-child(even) td {{
            background: rgba(148, 163, 184, 0.08);
        }}

        blockquote {{
            margin: 24px 0;
            padding: 18px 24px;
            border-left: 4px solid var(--brand);
            background: var(--brand-soft);
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            color: var(--slate-700);
            font-style: italic;
        }}

        a {{
            color: var(--brand-dark);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .pager {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 48px;
            padding-top: 24px;
            border-top: 1px solid var(--slate-200);
            gap: 16px;
        }}

        .pager-link {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            border-radius: var(--radius-sm);
            background: rgba(37, 99, 235, 0.08);
            color: var(--brand-dark);
            font-weight: 600;
        }}

        .pager-link:hover {{
            background: rgba(37, 99, 235, 0.18);
            text-decoration: none;
        }}

        .page-footer {{
            margin-top: 32px;
            font-size: 0.88rem;
            color: var(--slate-600);
        }}

        .no-nav {{
            justify-content: flex-end;
        }}

        @media (max-width: 1080px) {{
            .page {{
                grid-template-columns: minmax(0, 1fr);
            }}

            .sidebar {{
                position: relative;
                min-height: auto;
                border-radius: 0 0 var(--radius-md) var(--radius-md);
            }}

            .content {{
                padding: 32px 24px;
            }}

            .content-inner {{
                padding: 36px 26px;
            }}
        }}
    </style>
</head>
<body>
    <div class="page">
        <aside class="sidebar">
            <div class="brand"><a href="WIKI_HOME.html">Device Fingerprinting Docs</a></div>
            <div class="nav-title">Documentation</div>
            <ul class="nav-list">{navigation}</ul>
        </aside>
        <section class="content">
            <div class="content-inner">
                <header class="page-header">
                    <h1>{title}</h1>
                    <div class="page-meta">Generated on {generated_on}</div>
                </header>
                {toc_block}
                <article>
                    {content}
                </article>
                <footer class="page-footer">
                    <div class="pager {pager_class}">
                        {prev_link}
                        {next_link}
                    </div>
                </footer>
            </div>
        </section>
    </div>
</body>
</html>
"""  # noqa: E501


def load_pages(wiki_dir: Path) -> List[DocPage]:
    """Collect metadata for all wiki markdown files."""

    def sort_key(path: Path) -> tuple[int, str]:
        if path.stem == "WIKI_HOME":
            return (0, path.name)
        return (1, path.name)

    pages: List[DocPage] = []
    for md_path in sorted(wiki_dir.glob("WIKI_*.md"), key=sort_key):
        text = md_path.read_text(encoding="utf-8")
        title = extract_title(text) or md_path.stem.replace("_", " ")
        pages.append(
            DocPage(
                md_path=md_path,
                html_name=f"{md_path.stem}.html",
                title=title,
            )
        )
    return pages


def extract_title(markdown_text: str) -> Optional[str]:
    """Return the first level-one heading from the markdown text, if any."""

    for line in markdown_text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return None


def strip_leading_title(markdown_text: str) -> str:
    """Remove the first level-one heading so we can render it in the template."""

    lines = markdown_text.splitlines()
    if lines and lines[0].startswith("# "):
        return "\n".join(lines[1:]).lstrip()
    return markdown_text


def render_markdown(markdown_text: str) -> tuple[str, str]:
    """Render markdown into HTML content and an optional table of contents."""

    parser = Markdown(extensions=["toc", "fenced_code", "tables", "sane_lists", "admonition"])
    html_content = parser.convert(markdown_text)
    toc_html = parser.toc if getattr(parser, "toc", "").strip() else ""
    return html_content, toc_html


def build_navigation(pages: List[DocPage], current: DocPage) -> str:
    """Generate the navigation list markup."""

    nav_items: List[str] = []
    for page in pages:
        classes = ["nav-item"]
        if page == current:
            classes.append("active")
        class_attr = " ".join(classes)
        href = html.escape(page.html_name)
        label = html.escape(page.title)
        nav_item = '<li class="{cls}"><a href="{href}">{label}</a></li>'.format(
            cls=class_attr,
            href=href,
            label=label,
        )
        nav_items.append(nav_item)
    return "\n".join(nav_items)


def build_pager(pages: List[DocPage], current: DocPage) -> tuple[str, str, str]:
    """Construct previous/next navigation links for the current page."""

    index = pages.index(current)
    prev_link = ""
    next_link = ""

    if index > 0:
        prev_page = pages[index - 1]
        prev_href = html.escape(prev_page.html_name)
        prev_label = html.escape(prev_page.title)
        prev_link = (
            '<a class="pager-link prev" href="{href}">' "&#8592; {label}</a>"
        ).format(href=prev_href, label=prev_label)

    if index < len(pages) - 1:
        next_page = pages[index + 1]
        next_href = html.escape(next_page.html_name)
        next_label = html.escape(next_page.title)
        next_link = (
            '<a class="pager-link next" href="{href}">' "{label} &#8594;</a>"
        ).format(href=next_href, label=next_label)

    pager_class = "no-nav" if not prev_link and not next_link else ""
    return prev_link or "", next_link or "", pager_class


def rewrite_internal_links(html_content: str, link_map: Dict[str, str]) -> str:
    """Switch internal markdown links from .md to .html targets."""

    def replace(match: re.Match[str]) -> str:
        href = match.group(1)
        anchor = match.group(2) or ""
        if href in link_map:
            return f'href="{link_map[href]}{anchor}"'
        return match.group(0)

    pattern = re.compile(r'href="([^\"]+\.md)(#[^\"]*)?"')
    return pattern.sub(replace, html_content)


def convert_page(pages: List[DocPage], page: DocPage, link_map: Dict[str, str]) -> Path:
    """Render a single markdown document into the HTML template."""

    markdown_text = page.md_path.read_text(encoding="utf-8")
    content_without_title = strip_leading_title(markdown_text)
    html_content, toc_html = render_markdown(content_without_title)
    toc_html = toc_html.strip()
    wrapper_start = '<div class="toc">'
    wrapper_end = "</div>"
    if toc_html.startswith(wrapper_start) and toc_html.endswith(wrapper_end):
        start = len(wrapper_start)
        end = len(wrapper_end)
        toc_html = toc_html[start:-end].strip()
    html_content = rewrite_internal_links(html_content, link_map)
    toc_block = ""
    if toc_html:
        toc_block = (
            '<aside class="doc-toc"><strong>On this page</strong>' "{content}</aside>"
        ).format(content=toc_html)

    navigation = build_navigation(pages, page)
    prev_link, next_link, pager_class = build_pager(pages, page)
    generated_on = datetime.now().strftime("%Y-%m-%d %H:%M")

    html_output = HTML_TEMPLATE.format(
        title=html.escape(page.title),
        navigation=navigation,
        toc_block=toc_block,
        content=html_content,
        prev_link=prev_link,
        next_link=next_link,
        pager_class=pager_class,
        generated_on=generated_on,
    )

    output_path = page.md_path.with_suffix(".html")
    output_path.write_text(html_output, encoding="utf-8")
    return output_path


def main() -> None:
    """Convert all wiki markdown files in the repository root."""

    repo_root = Path(__file__).parent
    pages = load_pages(repo_root)

    if not pages:
        print("No WIKI_*.md files found")
        return

    link_map = {page.md_path.name: page.html_name for page in pages}

    print(f"Found {len(pages)} wiki files to convert:\n")

    generated_files: List[Path] = []
    for page in pages:
        html_path = convert_page(pages, page, link_map)
        generated_files.append(html_path)
        print(f"  - {page.md_path.name} \u2192 {html_path.name}")

    print("\n\u2713 Conversion complete. HTML files generated:")
    for html_path in generated_files:
        print(f"    • {html_path.name}")

    print("\nOpen WIKI_HOME.html in your browser to start navigating " "the documentation.")


if __name__ == "__main__":  # pragma: no cover
    main()
