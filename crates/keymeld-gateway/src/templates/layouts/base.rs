use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::templates::components::{navbar, theme};

pub struct PageConfig<'a> {
    pub title: &'a str,
    pub current_page: CurrentPage,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CurrentPage {
    Dashboard,
    Sessions,
    Enclaves,
}

pub fn base(config: &PageConfig, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (config.title) }
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.4/css/bulma.min.css";
                link rel="stylesheet" href="/static/styles.min.css";
                script src="https://unpkg.com/htmx.org@1.9.10" {}
                // Apply saved theme before page renders to prevent flash
                script { (PreEscaped(THEME_INIT_SCRIPT)) }
            }
            body {
                section class="section" {
                    div class="container" {
                        // Header with title and links
                        nav class="level mb-4" {
                            div class="level-left" {
                                a href="/" class="has-text-current" style="text-decoration: none;" {
                                    h1 class="title level-item" { "KeyMeld Admin" }
                                }
                            }
                            div class="level-right" {
                                p class="level-item" {
                                    (theme::theme_toggle())
                                    a href="/api/v1/docs" class="button is-link is-light is-small ml-2 mr-2" {
                                        "API Docs"
                                    }
                                    a href="https://github.com/tee8z/keymeld" target="_blank"
                                      class="has-text-current" {
                                        (github_icon())
                                    }
                                }
                            }
                        }

                        // Navigation bar
                        (navbar::navbar(config.current_page))

                        // Main content area
                        div id="main-content" {
                            (content)
                        }
                    }
                }

                script type="module" src="/static/loader.js" {}
            }
        }
    }
}

/// Script to initialize theme from localStorage before page renders
const THEME_INIT_SCRIPT: &str = r#"
(function() {
    const saved = localStorage.getItem('keymeld-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
})();
"#;

fn github_icon() -> Markup {
    html! {
        svg height="24" width="24" viewBox="0 0 16 16" version="1.1" aria-hidden="true"
            style="fill: currentColor; vertical-align: middle;" {
            path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" {}
        }
    }
}
