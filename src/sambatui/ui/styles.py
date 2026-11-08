APP_CSS = """
Screen {
    layout: vertical;
    background: $background;
}


#main {
    height: 1fr;
    padding: 1;
}

#sidebar {
    width: 36%;
    min-width: 30;
    max-width: 44;
    height: 1fr;
    margin-right: 1;
}

#side_tabs, #results, #dns_panel, #ldap_panel { height: 1fr; }
#results { width: 1fr; }

.panel {
    border: round $border-blurred;
    padding: 0 1;
}
.panel:focus-within { border: round $border; }

.section-title {
    text-style: bold;
    color: $text;
    margin-bottom: 1;
}
#records_header { height: 3; align-vertical: middle; }
#records_title { width: 1fr; }
#selection_state {
    display: none;
    width: auto;
    margin-right: 2;
    color: $accent;
    text-style: bold;
}
#inline_search { width: 32; }
.hint { color: $text-muted; margin-bottom: 1; }
#connection_summary { color: $text-muted; padding: 0 1; }
#keys {
    height: 2;
    padding: 0 2;
    color: $text-muted;
    content-align: left middle;
}

Button { width: 1fr; }
DataTable { background: $background; }

#zones, #ldap_structure { height: 2fr; margin-bottom: 1; }
#dns_findings, #ldap_findings { height: 1fr; max-height: 10; }
#records { height: 1fr; }
#record_details {
    height: 9;
    margin-top: 1;
    border-top: solid $border-blurred;
    padding: 1;
    overflow-y: auto;
    color: $text;
}
#status {
    height: 2;
    padding: 0 1;
    color: $text-muted;
    content-align: left middle;
}
"""
