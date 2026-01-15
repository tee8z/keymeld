use maud::{html, Markup};

use crate::templates::layouts::CurrentPage;

/// Navigation bar component
pub fn navbar(current_page: CurrentPage) -> Markup {
    html! {
        nav class="navbar mb-4" role="navigation" aria-label="main navigation" {
            div class="navbar-brand" {
                a class="navbar-burger" role="button" aria-label="menu" aria-expanded="false" data-target="navbarMenu" {
                    span aria-hidden="true" {}
                    span aria-hidden="true" {}
                    span aria-hidden="true" {}
                }
            }

            div id="navbarMenu" class="navbar-menu" {
                div class="navbar-start" {
                    a class=(nav_class(current_page, CurrentPage::Dashboard))
                      href="/"
                      hx-get="/"
                      hx-target="#main-content"
                      hx-push-url="true" {
                        span class="icon is-small mr-1" { (dashboard_icon()) }
                        "Dashboard"
                    }
                    a class=(nav_class(current_page, CurrentPage::Sessions))
                      href="/sessions"
                      hx-get="/sessions"
                      hx-target="#main-content"
                      hx-push-url="true" {
                        span class="icon is-small mr-1" { (sessions_icon()) }
                        "Sessions"
                    }
                    a class=(nav_class(current_page, CurrentPage::Enclaves))
                      href="/enclaves"
                      hx-get="/enclaves"
                      hx-target="#main-content"
                      hx-push-url="true" {
                        span class="icon is-small mr-1" { (enclaves_icon()) }
                        "Enclaves"
                    }
                }
            }
        }
    }
}

fn nav_class(current: CurrentPage, target: CurrentPage) -> &'static str {
    if current == target {
        "navbar-item is-active"
    } else {
        "navbar-item"
    }
}

fn dashboard_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" {
            rect x="3" y="3" width="7" height="7" {}
            rect x="14" y="3" width="7" height="7" {}
            rect x="14" y="14" width="7" height="7" {}
            rect x="3" y="14" width="7" height="7" {}
        }
    }
}

fn sessions_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" {
            path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" {}
            polyline points="14 2 14 8 20 8" {}
            line x1="16" y1="13" x2="8" y2="13" {}
            line x1="16" y1="17" x2="8" y2="17" {}
            polyline points="10 9 9 9 8 9" {}
        }
    }
}

fn enclaves_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
            stroke-linejoin="round" {
            rect x="4" y="4" width="16" height="16" rx="2" ry="2" {}
            rect x="9" y="9" width="6" height="6" {}
            line x1="9" y1="1" x2="9" y2="4" {}
            line x1="15" y1="1" x2="15" y2="4" {}
            line x1="9" y1="20" x2="9" y2="23" {}
            line x1="15" y1="20" x2="15" y2="23" {}
            line x1="20" y1="9" x2="23" y2="9" {}
            line x1="20" y1="14" x2="23" y2="14" {}
            line x1="1" y1="9" x2="4" y2="9" {}
            line x1="1" y1="14" x2="4" y2="14" {}
        }
    }
}
