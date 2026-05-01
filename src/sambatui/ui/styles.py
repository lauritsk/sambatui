APP_CSS = """
Screen { layout: vertical; }

#connection_state { display: none; }

#main {
    height: 1fr;
    margin: 0 1;
}

#sidebar {
    width: 42;
    min-width: 34;
    height: 1fr;
    margin-right: 1;
}

#side_tabs { height: 1fr; }

#results {
    width: 1fr;
    height: 1fr;
}

.panel {
    border: tall $surface;
    padding: 0 1;
}

#dns_panel, #ldap_panel, #smart_panel { height: 1fr; }
.action-buttons { height: auto; margin-bottom: 1; }
.action-buttons Button { margin-bottom: 1; }

.section-title { text-style: bold; color: $accent; margin-bottom: 1; }
#records_header { height: 3; }
#records_title { width: 1fr; }
#inline_search { width: 36; }
.hint { color: $text-muted; margin-bottom: 1; }
#connection_summary { color: $text-muted; margin-bottom: 1; }
#keys { height: 1; margin: 0 1; color: $text-muted; }

Button { width: 1fr; }

#zones { height: 1fr; margin-bottom: 1; }
#ldap_hint { height: 1fr; }
#records { height: 1fr; }
#record_details {
    height: 10;
    margin-top: 1;
    border: tall $surface;
    padding: 0 1;
    overflow-y: auto;
    color: $text;
}
#status { height: 3; color: $text-muted; }
"""
