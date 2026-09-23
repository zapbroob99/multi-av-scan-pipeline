// Generated from contracts/browser.openapi.json. Do not edit.
export interface paths {
    "/api/ui/v1/about": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser About */
        get: operations["browser_about_api_ui_v1_about_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/account": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Own Account */
        get: operations["own_account_api_ui_v1_account_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/account/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change Own Password */
        post: operations["change_own_password_api_ui_v1_account_password_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Api Ledger */
        get: operations["browser_api_ledger_api_ui_v1_api_ledger_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/batches/{batch_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Batch */
        get: operations["automation_batch_api_ui_v1_api_ledger_batches__batch_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/batches/{batch_id}/download": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Batch Download */
        get: operations["automation_batch_download_api_ui_v1_api_ledger_batches__batch_id__download_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/batches/{batch_id}/json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Batch Json */
        get: operations["automation_batch_json_api_ui_v1_api_ledger_batches__batch_id__json_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Bulk Delete Automation Scans */
        delete: operations["bulk_delete_automation_scans_api_ui_v1_api_ledger_scans_delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Report */
        get: operations["automation_report_api_ui_v1_api_ledger_scans__scan_id__get"];
        put?: never;
        post?: never;
        /** Delete Automation Scan */
        delete: operations["delete_automation_scan_api_ui_v1_api_ledger_scans__scan_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/children": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Automation Archive Children */
        get: operations["read_automation_archive_children_api_ui_v1_api_ledger_scans__scan_id__children_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/export": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Full Export */
        get: operations["automation_full_export_api_ui_v1_api_ledger_scans__scan_id__export_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/print": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Printable Report */
        get: operations["automation_printable_report_api_ui_v1_api_ledger_scans__scan_id__print_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/result-json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Result Json */
        get: operations["automation_result_json_api_ui_v1_api_ledger_scans__scan_id__result_json_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Technical */
        get: operations["automation_technical_api_ui_v1_api_ledger_scans__scan_id__results__result_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}/full": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Full Output */
        get: operations["automation_full_output_api_ui_v1_api_ledger_scans__scan_id__results__result_id__full_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/results/{result_id}/output": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Result Output */
        get: operations["automation_result_output_api_ui_v1_api_ledger_scans__scan_id__results__result_id__output_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/status-json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Status Json */
        get: operations["automation_status_json_api_ui_v1_api_ledger_scans__scan_id__status_json_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/api-ledger/scans/{scan_id}/summary-export": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Automation Summary Export */
        get: operations["automation_summary_export_api_ui_v1_api_ledger_scans__scan_id__summary_export_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Audit */
        get: operations["browser_audit_api_ui_v1_audit_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/batches/{batch_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Manual Batch */
        get: operations["read_manual_batch_api_ui_v1_batches__batch_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/dashboard/scans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Dashboard Scans */
        get: operations["dashboard_scans_api_ui_v1_dashboard_scans_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/dashboard/summary": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Dashboard Summary */
        get: operations["dashboard_summary_api_ui_v1_dashboard_summary_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Engines */
        get: operations["engines_api_ui_v1_engines_get"];
        put?: never;
        /** Create Engine */
        post: operations["create_engine_api_ui_v1_engines_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Delete Engine */
        delete: operations["delete_engine_api_ui_v1_engines__instance_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/checks": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Check Engine */
        post: operations["check_engine_api_ui_v1_engines__instance_id__checks_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/config": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Configure Engine */
        put: operations["configure_engine_api_ui_v1_engines__instance_id__config_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/enabled": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Enable Engine */
        put: operations["enable_engine_api_ui_v1_engines__instance_id__enabled_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/placement": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Placement */
        put: operations["placement_api_ui_v1_engines__instance_id__placement_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/rules": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Rules */
        get: operations["rules_api_ui_v1_engines__instance_id__rules_get"];
        put?: never;
        /** Upload Rule */
        post: operations["upload_rule_api_ui_v1_engines__instance_id__rules_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/rules/{name}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Delete Rule */
        delete: operations["delete_rule_api_ui_v1_engines__instance_id__rules__name__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/engines/{instance_id}/rules/{name}/toggle": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Toggle Rule */
        post: operations["toggle_rule_api_ui_v1_engines__instance_id__rules__name__toggle_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/hash-list": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Hash List */
        get: operations["browser_hash_list_api_ui_v1_hash_list_get"];
        put?: never;
        /** Browser Add Hashes */
        post: operations["browser_add_hashes_api_ui_v1_hash_list_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/hash-list/{entry_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Browser Remove Hash */
        delete: operations["browser_remove_hash_api_ui_v1_hash_list__entry_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/hash-scan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Browser Hash Lookup */
        post: operations["browser_hash_lookup_api_ui_v1_hash_scan_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/hash-scan/options": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Hash Lookup Options */
        get: operations["read_hash_lookup_options_api_ui_v1_hash_scan_options_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scan-policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Browser Scan Policy */
        get: operations["read_browser_scan_policy_api_ui_v1_scan_policy_get"];
        /** Save Browser Scan Policy */
        put: operations["save_browser_scan_policy_api_ui_v1_scan_policy_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit Scan */
        post: operations["submit_scan_api_ui_v1_scans_post"];
        /** Bulk Delete Manual Scans */
        delete: operations["bulk_delete_manual_scans_api_ui_v1_scans_delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Scan Report */
        get: operations["read_scan_report_api_ui_v1_scans__scan_id__get"];
        put?: never;
        post?: never;
        /** Delete Manual Scan */
        delete: operations["delete_manual_scan_api_ui_v1_scans__scan_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/children": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Archive Children */
        get: operations["read_archive_children_api_ui_v1_scans__scan_id__children_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/export": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export Scan Full */
        get: operations["export_scan_full_api_ui_v1_scans__scan_id__export_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/print": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Manual Printable Report */
        get: operations["manual_printable_report_api_ui_v1_scans__scan_id__print_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/results/{result_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Scan Technical Details */
        get: operations["read_scan_technical_details_api_ui_v1_scans__scan_id__results__result_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/results/{result_id}/full": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Full Engine Output */
        get: operations["read_full_engine_output_api_ui_v1_scans__scan_id__results__result_id__full_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/results/{result_id}/output": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Manual Result Output */
        get: operations["manual_result_output_api_ui_v1_scans__scan_id__results__result_id__output_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/retry": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Retry Manual Scan */
        post: operations["retry_manual_scan_api_ui_v1_scans__scan_id__retry_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/{scan_id}/summary-export": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export Scan Summary */
        get: operations["export_scan_summary_api_ui_v1_scans__scan_id__summary_export_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/scans/options": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Submission Options */
        get: operations["submission_options_api_ui_v1_scans_options_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Browser Service Clients */
        get: operations["read_browser_service_clients_api_ui_v1_service_clients_get"];
        put?: never;
        /** Browser Create Client */
        post: operations["browser_create_client_api_ui_v1_service_clients_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Update Browser Service Client */
        put: operations["update_browser_service_client_api_ui_v1_service_clients__client_id__put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/credentials": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Credentials */
        get: operations["browser_credentials_api_ui_v1_service_clients__client_id__credentials_get"];
        put?: never;
        /** Browser Create Credential */
        post: operations["browser_create_credential_api_ui_v1_service_clients__client_id__credentials_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/credentials/{credential_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Browser Revoke Credential */
        post: operations["browser_revoke_credential_api_ui_v1_service_clients__client_id__credentials__credential_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/profiles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Browser Profiles */
        get: operations["read_browser_profiles_api_ui_v1_service_clients__client_id__profiles_get"];
        put?: never;
        /** Create Browser Profile */
        post: operations["create_browser_profile_api_ui_v1_service_clients__client_id__profiles_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Update Browser Profile */
        put: operations["update_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__put"];
        post?: never;
        /** Delete Browser Profile */
        delete: operations["delete_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/default": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Default Browser Profile */
        put: operations["default_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__default_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/profiles/{profile_id}/engines": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Save Browser Profile */
        put: operations["save_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__engines_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Client Readiness */
        get: operations["browser_client_readiness_api_ui_v1_service_clients__client_id__readiness_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/{client_id}/storage": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Browser Client Storage */
        get: operations["read_browser_client_storage_api_ui_v1_service_clients__client_id__storage_get"];
        /** Save Browser Client Storage */
        put: operations["save_browser_client_storage_api_ui_v1_service_clients__client_id__storage_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/service-clients/create-options": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Client Create Options */
        get: operations["browser_client_create_options_api_ui_v1_service_clients_create_options_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/session": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Session */
        get: operations["session_api_ui_v1_session_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/session/login": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Sign In */
        post: operations["sign_in_api_ui_v1_session_login_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/session/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Sign Out */
        post: operations["sign_out_api_ui_v1_session_logout_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/engine-metrics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Engine Metrics */
        get: operations["read_engine_metrics_api_ui_v1_system_engine_metrics_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/pools": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Worker Pools */
        get: operations["read_worker_pools_api_ui_v1_system_pools_get"];
        put?: never;
        /** Create Browser Pool */
        post: operations["create_browser_pool_api_ui_v1_system_pools_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/pools/{pool_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Update Browser Pool */
        put: operations["update_browser_pool_api_ui_v1_system_pools__pool_id__put"];
        post?: never;
        /** Delete Browser Pool */
        delete: operations["delete_browser_pool_api_ui_v1_system_pools__pool_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/queue": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Active Queue */
        get: operations["read_active_queue_api_ui_v1_system_queue_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/retention": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read Retention Candidates */
        get: operations["read_retention_candidates_api_ui_v1_system_retention_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/retention/run": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run Browser Retention */
        post: operations["run_browser_retention_api_ui_v1_system_retention_run_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/summary": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read System Summary */
        get: operations["read_system_summary_api_ui_v1_system_summary_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/workers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read System Workers */
        get: operations["read_system_workers_api_ui_v1_system_workers_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/workers/credentials/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Worker Credentials */
        post: operations["revoke_worker_credentials_api_ui_v1_system_workers_credentials_revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/system/workers/lifecycle": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change Worker Lifecycle */
        post: operations["change_worker_lifecycle_api_ui_v1_system_workers_lifecycle_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/users": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Browser Users */
        get: operations["browser_users_api_ui_v1_users_get"];
        put?: never;
        /** Browser Create User */
        post: operations["browser_create_user_api_ui_v1_users_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/ui/v1/users/{user_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Browser Update User */
        put: operations["browser_update_user_api_ui_v1_users__user_id__put"];
        post?: never;
        /** Browser Delete User */
        delete: operations["browser_delete_user_api_ui_v1_users__user_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** AboutPayload */
        AboutPayload: {
            /** App Version */
            app_version: string;
            /** Directory Login Enabled */
            directory_login_enabled: boolean;
            /** Enabled Engine Count */
            enabled_engine_count: number;
            /** Enabled Engine Names */
            enabled_engine_names: string[];
            /** Engine Names Truncated */
            engine_names_truncated: boolean;
            /** Generated At */
            generated_at: string;
            /** Hash Engine Count */
            hash_engine_count: number;
            /** Queue Mode */
            queue_mode: string;
            /** Registered Nodes */
            registered_nodes: number;
            /** Schedulable Nodes */
            schedulable_nodes: number;
            /** Secret Encryption Available */
            secret_encryption_available: boolean;
            /** Service Client Count */
            service_client_count: number | null;
            /** Worker Transport */
            worker_transport: string;
        };
        /** AccountPayload */
        AccountPayload: {
            /** Auth Source */
            auth_source: string;
            /** Role */
            role: string;
            /** User Id */
            user_id: number;
            /** Username */
            username: string;
        };
        /** ActiveQueuePage */
        ActiveQueuePage: {
            /** Items */
            items: components["schemas"]["ActiveScan"][];
            /** Next After */
            next_after: number | null;
        };
        /** ActiveScan */
        ActiveScan: {
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Id */
            id: number;
            /** Priority */
            priority: string;
            /** Source */
            source: string;
            /** Status */
            status: string;
        };
        /** AdapterPayload */
        AdapterPayload: {
            capabilities: components["schemas"]["EngineCapabilityProfile"];
            /** Description */
            description: string;
            /** Fields */
            fields: components["schemas"]["FieldPayload"][];
            /** Key */
            key: string;
            /** Label */
            label: string;
            /** Support State */
            support_state: string;
        };
        /** AddHashesBody */
        AddHashesBody: {
            /** Hashes */
            hashes: string[];
            /**
             * List Kind
             * @enum {string}
             */
            list_kind: "block" | "allow";
            /**
             * Note
             * @default
             */
            note?: string;
        };
        /** ArchiveChild */
        ArchiveChild: {
            /** Filename */
            filename: string;
            /** Has Children */
            has_children: boolean;
            /** Id */
            id: number;
            /** Path */
            path: string;
            /** Path Truncated */
            path_truncated: boolean;
            /** Risk Level */
            risk_level: string;
            /** Risk Score */
            risk_score: number | null;
            /** Size Bytes */
            size_bytes: number;
            /** Status */
            status: string;
        };
        /** ArchivePage */
        ArchivePage: {
            /** Archive Mode */
            archive_mode: string | null;
            /** Attempt Count */
            attempt_count: number;
            /** Batch Id */
            batch_id: number | null;
            /** Items */
            items: components["schemas"]["ArchiveChild"][];
            /** Next After */
            next_after: number | null;
            /** Parent Filename */
            parent_filename: string;
            /** Parent Id */
            parent_id: number;
            /** Parent Scan Id */
            parent_scan_id: number | null;
            /** Parent Status */
            parent_status: string;
        };
        /** AssignedEngine */
        AssignedEngine: {
            /** Adapter Key */
            adapter_key: string;
            /** Display Name */
            display_name: string;
            /** Eligible */
            eligible: boolean;
            /** Enabled */
            enabled: boolean;
            /** Excluded Reason */
            excluded_reason: string | null;
            /** Id */
            id: number;
        };
        /** AuditEvent */
        AuditEvent: {
            /** Action */
            action: string;
            /** Actor Id */
            actor_id: string | null;
            /** Actor Name */
            actor_name: string | null;
            /** Actor Type */
            actor_type: string;
            /** Created At */
            created_at: string;
            /** Details */
            details: string;
            /** Details Truncated */
            details_truncated: boolean;
            /** Id */
            id: number;
            /** Outcome */
            outcome: string;
            /** Request Id */
            request_id: string;
            /** Source Ip */
            source_ip: string | null;
            /** Target Id */
            target_id: string | null;
            /** Target Type */
            target_type: string;
        };
        /** AuditPage */
        AuditPage: {
            /** Items */
            items: components["schemas"]["AuditEvent"][];
            /** Next Before */
            next_before: number | null;
        };
        /** BatchCounts */
        BatchCounts: {
            /** Completed */
            completed: number;
            /** Failed */
            failed: number;
            /** Malicious */
            malicious: number;
            /** Queued */
            queued: number;
            /** Running */
            running: number;
            /** Skipped */
            skipped: number;
            /** Total */
            total: number;
        };
        /** BatchPage */
        BatchPage: {
            /** Archive Mode */
            archive_mode: string;
            /** Batch Id */
            batch_id: number;
            /** Completed At */
            completed_at: string | null;
            counts: components["schemas"]["BatchCounts"];
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Filename Truncated */
            filename_truncated: boolean;
            /** Items */
            items: components["schemas"]["BatchScan"][];
            /** Next After Created */
            next_after_created: string | null;
            /** Next After Id */
            next_after_id: number | null;
            /** Service Client Id */
            service_client_id?: number | null;
            /**
             * Source
             * @default manual
             */
            source?: string;
            /** Status */
            status: string;
            /** Updated At */
            updated_at: string;
        };
        /** BatchPreview */
        BatchPreview: {
            /** Batch Id */
            batch_id: number;
            /** Content */
            content: string;
        };
        /** BatchScan */
        BatchScan: {
            /** Attempt Count */
            attempt_count: number;
            /** Completed At */
            completed_at: string | null;
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Id */
            id: number;
            /** Parent Scan Id */
            parent_scan_id: number | null;
            /** Path */
            path: string;
            /** Path Truncated */
            path_truncated: boolean;
            /** Risk Level */
            risk_level: string;
            /** Risk Score */
            risk_score: number | null;
            /** Role */
            role: string;
            /** Size Bytes */
            size_bytes: number;
            /** Status */
            status: string;
        };
        /** Body_submit_scan_api_ui_v1_scans_post */
        Body_submit_scan_api_ui_v1_scans_post: {
            /**
             * Case Name
             * @default Unassigned
             */
            case_name?: string;
            /**
             * Note
             * @default
             */
            note?: string;
            /**
             * Priority
             * @default Normal
             * @enum {string}
             */
            priority?: "Normal" | "High" | "Low";
            /** Sample */
            sample: string;
        };
        /** BulkDeleteBody */
        BulkDeleteBody: {
            /** Scans */
            scans: components["schemas"]["BulkDeleteCandidate"][];
        };
        /** BulkDeleteCandidate */
        BulkDeleteCandidate: {
            /** Attempt */
            attempt: number;
            /** Job Revision */
            job_revision: number;
            /** Scan Id */
            scan_id: number;
        };
        /** BulkDeleteResult */
        BulkDeleteResult: {
            /** Blocked Ids */
            blocked_ids: number[];
            /** Cleanup Failed Ids */
            cleanup_failed_ids: number[];
            /** Deleted Ids */
            deleted_ids: number[];
            /** Requested Count */
            requested_count: number;
        };
        /** ClientCreateBody */
        ClientCreateBody: {
            /**
             * Api Token
             * Format: password
             */
            api_token: string;
            /** Client Key */
            client_key: string;
            /** Credential Label */
            credential_label: string;
            /** Display Name */
            display_name: string;
            /** Engine Ids */
            engine_ids: number[];
            /** Profile Name */
            profile_name: string;
        };
        /** ClientCreated */
        ClientCreated: {
            /** Client Id */
            client_id: number;
            /** Credential Id */
            credential_id: number;
            /** Profile Id */
            profile_id: number;
        };
        /** ClientCreateOptions */
        ClientCreateOptions: {
            /** Engines */
            engines: components["schemas"]["ProfileEngineChoice"][];
            /** Incomplete */
            incomplete: boolean;
        };
        /** ClientProfiles */
        ClientProfiles: {
            /** Client Id */
            client_id: number;
            /** Default Profile Id */
            default_profile_id: number | null;
            /** Engines */
            engines: components["schemas"]["ProfileEngineChoice"][];
            /** Engines Incomplete */
            engines_incomplete: boolean;
            /** Items */
            items: components["schemas"]["ProfileSummary"][];
            /** Managed */
            managed: boolean;
            /** Next After */
            next_after: number | null;
        };
        /** ClientReadiness */
        ClientReadiness: {
            /** Active Credential Count */
            active_credential_count: number;
            /** Authorization Header */
            authorization_header: string;
            /** Checks */
            checks: components["schemas"]["ReadinessCheck"][];
            /** Client Id */
            client_id: number;
            /** Client Key */
            client_key: string;
            /** Deferred Endpoint */
            deferred_endpoint: string;
            /** Display Name */
            display_name: string;
            /** Eligible Engine Count */
            eligible_engine_count: number;
            /** Enabled */
            enabled: boolean;
            /** Engines */
            engines: components["schemas"]["AssignedEngine"][];
            /** Generated At */
            generated_at: string;
            /** Icap Client Key Setting */
            icap_client_key_setting: string;
            /** Managed */
            managed: boolean;
            /** Profile Id */
            profile_id: number | null;
            /** Profile Name */
            profile_name: string | null;
            /** Ready */
            ready: boolean;
            /** Scan Endpoint */
            scan_endpoint: string;
            /** Status Endpoint */
            status_endpoint: string;
        };
        /** ClientStorageAccess */
        ClientStorageAccess: {
            /** Backends */
            backends: string[];
            /** Client Id */
            client_id: number;
            /** Environment Fingerprint */
            environment_fingerprint: string;
            /** Environment Grants */
            environment_grants: components["schemas"]["StorageGrant"][];
            /** Grants */
            grants: components["schemas"]["StorageGrant"][];
            /** Managed */
            managed: boolean;
            /**
             * Mode
             * @enum {string}
             */
            mode: "environment" | "custom";
            /** Revision */
            revision: number;
        };
        /** ConfigBody */
        ConfigBody: {
            /** Config */
            config: {
                [key: string]: string;
            };
        };
        /** CreateBody */
        CreateBody: {
            /** Adapter Key */
            adapter_key: string;
            /** Config */
            config: {
                [key: string]: string;
            };
            /** Display Name */
            display_name: string;
        };
        /** CreateUserBody */
        CreateUserBody: {
            /**
             * Password
             * Format: password
             */
            password: string;
            /**
             * Role
             * @enum {string}
             */
            role: "admin" | "analyst";
            /** Username */
            username: string;
        };
        /** CredentialBody */
        CredentialBody: {
            /**
             * Api Token
             * Format: password
             */
            api_token: string;
            /** Credential Label */
            credential_label: string;
        };
        /** CredentialCreated */
        CredentialCreated: {
            /** Credential Id */
            credential_id: number;
        };
        /** CredentialPage */
        CredentialPage: {
            /** Items */
            items: components["schemas"]["CredentialSummary"][];
            /** Next After */
            next_after: number | null;
        };
        /** CredentialSummary */
        CredentialSummary: {
            /** Created At */
            created_at: string;
            /** Id */
            id: number;
            /** Label */
            label: string;
            /** Last Used At */
            last_used_at: number | null;
            /** Revoked At */
            revoked_at: number | null;
        };
        /** DashboardSummary */
        DashboardSummary: {
            /** Active */
            active: number;
            /** Enabled Engines */
            enabled_engines: number;
            /** Generated At */
            generated_at: string;
            /** High Risk */
            high_risk: number;
            /**
             * Refresh After Seconds
             * @default 30
             */
            refresh_after_seconds?: number;
            /** Total */
            total: number;
        };
        /** DecisionSummary */
        DecisionSummary: {
            /** Action */
            action: string;
            /** Confidence */
            confidence: string;
            /** Label */
            label: string;
            /** Policy */
            policy: string;
            /** Reason */
            reason: string;
            /** Reasons */
            reasons: string[];
            /** Tone */
            tone: string;
        };
        /** EnabledBody */
        EnabledBody: {
            /** Enabled */
            enabled: boolean;
        };
        /** EngineCapabilityProfile */
        EngineCapabilityProfile: {
            /**
             * Allows Multiple Instances
             * @default false
             */
            allows_multiple_instances?: boolean;
            /**
             * Consumes External Quota
             * @default false
             */
            consumes_external_quota?: boolean;
            /** Deployment */
            deployment: string;
            /** Execution Model */
            execution_model: string;
            /** Input Modes */
            input_modes: string[];
            /** Max File Size Bytes */
            max_file_size_bytes?: number | null;
            /**
             * Requires Database
             * @default false
             */
            requires_database?: boolean;
            /**
             * Requires Network
             * @default false
             */
            requires_network?: boolean;
            /** Supported Platforms */
            supported_platforms: string[];
            /**
             * Supports Archives
             * @default false
             */
            supports_archives?: boolean;
            /**
             * Supports File Hash Scan
             * @default false
             */
            supports_file_hash_scan?: boolean;
            /** Supports File Upload */
            supports_file_upload: boolean;
            /** Supports Hash Lookup */
            supports_hash_lookup: boolean;
            /**
             * Supports Rules
             * @default false
             */
            supports_rules?: boolean;
        };
        /** EngineMetric */
        EngineMetric: {
            /** Avg Duration Ms */
            avg_duration_ms: number | null;
            /** Completed */
            completed: number;
            /** Detections */
            detections: number;
            /** Engine Name */
            engine_name: string;
            /** Failed */
            failed: number;
            /** First Result Id */
            first_result_id: number;
            /** Max Duration Ms */
            max_duration_ms: number | null;
            /** Name Truncated */
            name_truncated: boolean;
            /** Skipped */
            skipped: number;
            /** Total */
            total: number;
        };
        /** EngineMetricPage */
        EngineMetricPage: {
            /** Generated At */
            generated_at: string;
            /** Items */
            items: components["schemas"]["EngineMetric"][];
            /** Next After */
            next_after: number | null;
        };
        /** EnginePayload */
        EnginePayload: {
            /** Adapter Key */
            adapter_key: string;
            /** Config */
            config: {
                [key: string]: string;
            };
            /** Display Name */
            display_name: string;
            /** Enabled */
            enabled: boolean;
            /** Has Secret */
            has_secret: boolean;
            health: components["schemas"]["HealthPayload"];
            /** Id */
            id: number;
            /** Pool Id */
            pool_id: number | null;
        };
        /** EngineSummary */
        EngineSummary: {
            /** Detected */
            detected: boolean;
            /** Duration Ms */
            duration_ms: number | null;
            /** Error */
            error: string | null;
            /** Name */
            name: string;
            /** Required */
            required: boolean;
            /** Result Id */
            result_id: number | null;
            /** Signature */
            signature: string | null;
            /** Status */
            status: string;
        };
        /** ErrorPayload */
        ErrorPayload: {
            /** Detail */
            detail: string;
        };
        /** ExistingHash */
        ExistingHash: {
            /**
             * List Kind
             * @enum {string}
             */
            list_kind: "block" | "allow" | "removed";
            /** Sha256 */
            sha256: string;
        };
        /** FieldPayload */
        FieldPayload: {
            /** Choices */
            choices: string[];
            /** Default */
            default: string;
            /** Field Type */
            field_type: string;
            /** Help Text */
            help_text: string;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /** Required */
            required: boolean;
            /** Secret */
            secret: boolean;
        };
        /** FullTechnicalDetails */
        FullTechnicalDetails: {
            /** Attempt Count */
            attempt_count: number;
            /** Details Json */
            details_json: string;
            /** Engine Name */
            engine_name: string;
            /** Findings Json */
            findings_json: string;
            /** Raw Output */
            raw_output: string;
            /** Result Id */
            result_id: number;
            /** Scan Id */
            scan_id: number;
        };
        /** HashEngineSummary */
        HashEngineSummary: {
            /** Id */
            id: number;
            /** Name */
            name: string;
        };
        /** HashesAdded */
        HashesAdded: {
            /** Added */
            added: number;
            /** Existing */
            existing: components["schemas"]["ExistingHash"][];
        };
        /** HashListCounts */
        HashListCounts: {
            /** Allow */
            allow: number;
            /** Block */
            block: number;
        };
        /** HashListEntry */
        HashListEntry: {
            /** Created At */
            created_at: number;
            /** Created By */
            created_by: string | null;
            /** Id */
            id: number;
            /**
             * List Kind
             * @enum {string}
             */
            list_kind: "block" | "allow";
            /** Note */
            note: string;
            /** Sha256 */
            sha256: string;
        };
        /** HashListPage */
        HashListPage: {
            counts: components["schemas"]["HashListCounts"] | null;
            /** Items */
            items: components["schemas"]["HashListEntry"][];
            /** Next Before */
            next_before: number | null;
        };
        /** HashLookupBody */
        HashLookupBody: {
            /** Sha256 */
            sha256: string;
        };
        /** HashLookupOptions */
        HashLookupOptions: {
            /** Engines */
            engines: components["schemas"]["HashEngineSummary"][];
        };
        /** HashLookupResult */
        HashLookupResult: {
            /**
             * Action
             * @enum {string}
             */
            action: "allow" | "review" | "block";
            /** Reason */
            reason: string;
            /** Results */
            results: components["schemas"]["HashLookupRow"][];
            /** Sha256 */
            sha256: string;
        };
        /** HashLookupRow */
        HashLookupRow: {
            /**
             * Action
             * @enum {string}
             */
            action: "allow" | "review" | "block";
            /** Found */
            found: boolean;
            /** Id */
            id: number;
            /** Name */
            name: string;
        };
        /** HealthPayload */
        HealthPayload: {
            /** Checked At */
            checked_at: number | null;
            /** Detail */
            detail: string;
            /** Ok */
            ok: boolean;
            /**
             * State
             * @enum {string}
             */
            state: "unknown" | "disabled" | "healthy" | "failed" | "unavailable" | "running" | "pending" | "stale";
        };
        /** InstanceEnabled */
        InstanceEnabled: {
            /** Enabled */
            enabled: boolean;
            /** Id */
            id: number;
        };
        /** InstanceSaved */
        InstanceSaved: {
            /** Id */
            id: number;
        };
        /** InventoryPayload */
        InventoryPayload: {
            /** Adapters */
            adapters: components["schemas"]["AdapterPayload"][];
            /** Engines */
            engines: components["schemas"]["EnginePayload"][];
            /** Pools */
            pools: components["schemas"]["PoolPayload"][];
        };
        /** LedgerPage */
        LedgerPage: {
            /** Items */
            items: components["schemas"]["LedgerScan"][];
            /** Next Before */
            next_before: number | null;
        };
        /** LedgerScan */
        LedgerScan: {
            /** Attempt Count */
            attempt_count: number;
            /** Batch Id */
            batch_id: number | null;
            /** Case Name */
            case_name: string;
            /** Client Name */
            client_name: string | null;
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Id */
            id: number;
            /** Job Revision */
            job_revision: number;
            /** Risk Level */
            risk_level: string;
            /** Risk Score */
            risk_score: number | null;
            /** Service Client Id */
            service_client_id: number | null;
            /** Sha256 */
            sha256: string;
            /** Size Bytes */
            size_bytes: number;
            /** Source */
            source: string;
            /** Status */
            status: string;
        };
        /** LoginBody */
        LoginBody: {
            /** Password */
            password: string;
            /** Username */
            username: string;
        };
        /** PasswordChangeBody */
        PasswordChangeBody: {
            /**
             * Confirm Password
             * Format: password
             */
            confirm_password: string;
            /**
             * Current Password
             * Format: password
             */
            current_password: string;
            /**
             * New Password
             * Format: password
             */
            new_password: string;
        };
        /** PlacementBody */
        PlacementBody: {
            /** Pool Id */
            pool_id: number | null;
        };
        /** PoolCreateBody */
        PoolCreateBody: {
            /** Name */
            name: string;
            /** Selector */
            selector: string;
        };
        /** PoolPage */
        PoolPage: {
            /** Items */
            items: components["schemas"]["PoolSummary"][];
            /** Next After */
            next_after: number | null;
        };
        /** PoolPayload */
        PoolPayload: {
            /** Enabled */
            enabled: boolean;
            /** Id */
            id: number;
            /** Name */
            name: string;
        };
        /** PoolSaved */
        PoolSaved: {
            /** Id */
            id: number;
        };
        /** PoolSummary */
        PoolSummary: {
            /** Enabled */
            enabled: boolean;
            /** Has Assignments */
            has_assignments: boolean;
            /** Id */
            id: number;
            /** Metadata Incomplete */
            metadata_incomplete: boolean;
            /** Name */
            name: string;
            /** Selector */
            selector: string;
        };
        /** PoolUpdateBody */
        PoolUpdateBody: {
            /** Enabled */
            enabled: boolean;
            /** Name */
            name: string;
            /** Selector */
            selector: string;
        };
        /** PrintableReport */
        PrintableReport: {
            /** Attempt Count */
            attempt_count: number;
            /** Case Name */
            case_name: string;
            /** Completed At */
            completed_at: string | null;
            /** Content Type */
            content_type: string;
            /** Created At */
            created_at: string;
            decision: components["schemas"]["DecisionSummary"] | null;
            /** Decision Warning */
            decision_warning: string | null;
            /** Engines */
            engines: components["schemas"]["PrintEngine"][];
            /** Filename */
            filename: string;
            /** Findings */
            findings: components["schemas"]["PrintFinding"][];
            /** Findings Truncated */
            findings_truncated: boolean;
            /** Generated At */
            generated_at: string;
            /** Note */
            note: string;
            /** Scan Id */
            scan_id: number;
            /** Sha256 */
            sha256: string;
            /** Size Bytes */
            size_bytes: number;
            /** Source */
            source: string;
            /** Status */
            status: string;
            summary: components["schemas"]["PrintSummary"];
        };
        /** PrintEngine */
        PrintEngine: {
            /** Confidence */
            confidence: number;
            /** Detected */
            detected: boolean;
            /** Duration Ms */
            duration_ms: number | null;
            /** Engine Name */
            engine_name: string;
            /** Error Message */
            error_message: string | null;
            /** Output Truncated */
            output_truncated: boolean;
            /** Raw Output */
            raw_output: string;
            /** Severity */
            severity: string;
            /** Signature */
            signature: string | null;
            /** Status */
            status: string;
        };
        /** PrintFinding */
        PrintFinding: {
            /** Classification */
            classification: string[];
            /** Engine */
            engine: string;
            /** Finding */
            finding: string;
            /** Matched Evidence */
            matched_evidence: string[];
            /** Severity */
            severity: string;
            /** Title */
            title: string;
        };
        /** PrintSummary */
        PrintSummary: {
            /** Assessment Reasons */
            assessment_reasons: string[];
            /** Coverage Detail */
            coverage_detail: string;
            /** Coverage Label */
            coverage_label: string;
            /** Coverage Ran */
            coverage_ran: number;
            /** Coverage Total */
            coverage_total: number;
            /** Coverage Unavailable */
            coverage_unavailable: string[];
            /** Detected Engines */
            detected_engines: string[];
            /** Detection Detail */
            detection_detail: string;
            /** Detection Label */
            detection_label: string;
            /** Risk Score */
            risk_score: number | null;
            /** Verdict */
            verdict: string;
        };
        /** ProfileCreateBody */
        ProfileCreateBody: {
            /** Engine Ids */
            engine_ids: number[];
            /** Name */
            name: string;
        };
        /** ProfileCreated */
        ProfileCreated: {
            /** Profile Id */
            profile_id: number;
        };
        /** ProfileDefaultBody */
        ProfileDefaultBody: {
            /** Expected Default Profile Id */
            expected_default_profile_id: number | null;
            /** Expected Revision */
            expected_revision: number;
        };
        /** ProfileEngineChoice */
        ProfileEngineChoice: {
            /** Adapter Key */
            adapter_key: string;
            /** Display Name */
            display_name: string;
            /** Enabled */
            enabled: boolean;
            /** Id */
            id: number;
        };
        /** ProfileFence */
        ProfileFence: {
            /** Expected Revision */
            expected_revision: number;
        };
        /** ProfileRoutingBody */
        ProfileRoutingBody: {
            /** Engine Ids */
            engine_ids: number[];
            /** Expected Engine Ids */
            expected_engine_ids: number[];
            /** Expected Revision */
            expected_revision?: number | null;
        };
        /** ProfileSummary */
        ProfileSummary: {
            /** Enabled */
            enabled: boolean;
            /** Engine Ids */
            engine_ids: number[];
            /** Id */
            id: number;
            /** Incomplete */
            incomplete: boolean;
            /** Is Default */
            is_default: boolean;
            /** Management Revision */
            management_revision: number;
            /** Name */
            name: string;
        };
        /** ProfileUpdateBody */
        ProfileUpdateBody: {
            /** Enabled */
            enabled: boolean;
            /** Expected Revision */
            expected_revision: number;
            /** Name */
            name: string;
        };
        /** ReadinessCheck */
        ReadinessCheck: {
            /** Detail */
            detail: string;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /** Passed */
            passed: boolean;
        };
        /** ResultPreview */
        ResultPreview: {
            /** Content */
            content: string;
            /** Scan Id */
            scan_id: number;
        };
        /** RetentionCandidate */
        RetentionCandidate: {
            /** Attempt */
            attempt: number;
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Job Revision */
            job_revision: number;
            /** Scan Id */
            scan_id: number;
            /** Source */
            source: string;
            /** Status */
            status: string;
        };
        /** RetentionPage */
        RetentionPage: {
            /** Batch Size */
            batch_size: number;
            /** Cutoff */
            cutoff: string | null;
            /** Days */
            days: number;
            /** Items */
            items: components["schemas"]["RetentionCandidate"][];
            /** Next After */
            next_after: number | null;
        };
        /** RetentionRunBody */
        RetentionRunBody: {
            /** Batch Size */
            batch_size: number;
            /** Days */
            days: number;
            /** Scans */
            scans: components["schemas"]["BulkDeleteCandidate"][];
        };
        /** RetryAccepted */
        RetryAccepted: {
            /** Scan Id */
            scan_id: number;
            /**
             * Status
             * @default accepted
             * @constant
             */
            status?: "accepted";
        };
        /** RuleBody */
        RuleBody: {
            /** Content */
            content: string;
            /** Filename */
            filename: string;
        };
        /** RulePayload */
        RulePayload: {
            /** Base Name */
            base_name: string;
            /** Enabled */
            enabled: boolean;
            /** Modified At */
            modified_at: number;
            /** Name */
            name: string;
            /** Size Bytes */
            size_bytes: number;
        };
        /** RuleSaved */
        RuleSaved: {
            /** Name */
            name: string;
        };
        /** RulesPayload */
        RulesPayload: {
            /** Rules */
            rules: components["schemas"]["RulePayload"][];
        };
        /** ScanAttemptBody */
        ScanAttemptBody: {
            /** Attempt */
            attempt: number;
            /** Job Revision */
            job_revision: number;
        };
        /** ScanDeleted */
        ScanDeleted: {
            /** Sample Removed */
            sample_removed: boolean;
            /** Scan Id */
            scan_id: number;
            /**
             * Status
             * @default deleted
             * @constant
             */
            status?: "deleted";
        };
        /** ScanPage */
        ScanPage: {
            /** Items */
            items: components["schemas"]["ScanPreview"][];
            /** Next Before */
            next_before: number | null;
        };
        /** ScanPolicyBody */
        ScanPolicyBody: {
            /** Api Max Wait Seconds */
            api_max_wait_seconds: string;
            /** Api Retry After Seconds */
            api_retry_after_seconds: string;
            /** Upload Max Bytes */
            upload_max_bytes: string;
        };
        /** ScanPolicyField */
        ScanPolicyField: {
            /** Default */
            default: number;
            /** Help */
            help: string;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /** Maximum */
            maximum: number;
            /** Minimum */
            minimum: number;
            /** Override Raw */
            override_raw: string;
            /** Source */
            source: string;
            /** Unit */
            unit: string;
            /** Value */
            value: number;
        };
        /** ScanPolicySnapshot */
        ScanPolicySnapshot: {
            /** Fields */
            fields: components["schemas"]["ScanPolicyField"][];
        };
        /** ScanPreview */
        ScanPreview: {
            /** Attempt Count */
            attempt_count: number;
            /** Case Name */
            case_name: string;
            /** Created At */
            created_at: string;
            /** Filename */
            filename: string;
            /** Id */
            id: number;
            /** Job Revision */
            job_revision: number;
            /** Risk Level */
            risk_level: string;
            /** Risk Score */
            risk_score: number | null;
            /** Sha256 */
            sha256: string;
            /** Size Bytes */
            size_bytes: number;
            /** Status */
            status: string;
        };
        /** ScanReport */
        ScanReport: {
            /** Attempt Count */
            attempt_count: number;
            /** Batch Id */
            batch_id: number | null;
            /** Case Name */
            case_name: string;
            /** Completed At */
            completed_at: string | null;
            /** Completed Engines */
            completed_engines: number;
            /** Coverage Basis */
            coverage_basis: string;
            /** Created At */
            created_at: string;
            decision: components["schemas"]["DecisionSummary"] | null;
            /** Detected Engines */
            detected_engines: number;
            /** Engines */
            engines: components["schemas"]["EngineSummary"][];
            /** Filename */
            filename: string;
            /** Id */
            id: number;
            /**
             * Job Revision
             * @default 0
             */
            job_revision?: number;
            /** Last Error */
            last_error: string | null;
            /** Note */
            note: string;
            /** Parent Scan Id */
            parent_scan_id: number | null;
            /** Required Engines */
            required_engines: number;
            /** Risk Level */
            risk_level: string;
            /** Risk Score */
            risk_score: number | null;
            /** Service Client Id */
            service_client_id?: number | null;
            /** Sha256 */
            sha256: string;
            /** Size Bytes */
            size_bytes: number;
            /**
             * Source
             * @default manual
             */
            source?: string;
            /** Status */
            status: string;
            /** Unavailable */
            unavailable: string[];
            /** Warning */
            warning: string | null;
        };
        /** ServiceClientPage */
        ServiceClientPage: {
            /** Items */
            items: components["schemas"]["ServiceClientSummary"][];
            /** Next After */
            next_after: number | null;
        };
        /** ServiceClientSummary */
        ServiceClientSummary: {
            /** Client Key */
            client_key: string;
            /** Display Name */
            display_name: string;
            /** Enabled */
            enabled: boolean;
            /** Id */
            id: number;
            /** Managed */
            managed: boolean;
            /** Metadata Incomplete */
            metadata_incomplete: boolean;
        };
        /** ServiceClientUpdate */
        ServiceClientUpdate: {
            /** Display Name */
            display_name: string;
            /** Enabled */
            enabled: boolean;
        };
        /** SessionPayload */
        SessionPayload: {
            /** Csrf Token */
            csrf_token: string;
            user: components["schemas"]["UserPayload"];
        };
        /** StorageAccessUpdate */
        StorageAccessUpdate: {
            /** Expected Environment Fingerprint */
            expected_environment_fingerprint: string;
            /** Expected Revision */
            expected_revision: number;
            /** Grants */
            grants: components["schemas"]["StorageGrant"][];
            /**
             * Mode
             * @enum {string}
             */
            mode: "environment" | "custom";
        };
        /** StorageGrant */
        StorageGrant: {
            /**
             * Access
             * @enum {string}
             */
            access: "all" | "prefixes";
            /** Backend Key */
            backend_key: string;
            /** Prefixes */
            prefixes?: string[];
        };
        /** SubmissionAccepted */
        SubmissionAccepted: {
            /** Report Url */
            report_url: string;
            /** Scan Id */
            scan_id: number;
            /**
             * Status
             * @default accepted
             * @constant
             */
            status?: "accepted";
        };
        /** SubmissionOptions */
        SubmissionOptions: {
            /** Archive Mode */
            archive_mode: string;
            /** Body Max Bytes */
            body_max_bytes: number;
            /** Enabled Engine Count */
            enabled_engine_count: number;
            /** File Max Bytes */
            file_max_bytes: number | null;
        };
        /** SummaryExport */
        SummaryExport: {
            /** Content */
            content: string;
            /** Filename */
            filename: string;
            /**
             * Media Type
             * @enum {string}
             */
            media_type: "application/json" | "text/csv";
        };
        /** SystemSummary */
        SystemSummary: {
            /** Active Online Nodes */
            active_online_nodes: number;
            /** Completed */
            completed: number;
            /** Failed */
            failed: number;
            /** Finalizing */
            finalizing: number;
            /** Generated At */
            generated_at: string;
            /** Online Nodes */
            online_nodes: number;
            /** Queued */
            queued: number;
            /** Registered Nodes */
            registered_nodes: number;
            /** Retention Batch Size */
            retention_batch_size: number;
            /** Retention Days */
            retention_days: number;
            /** Running */
            running: number;
            /** Total */
            total: number;
        };
        /** TechnicalDetails */
        TechnicalDetails: {
            /** Details Json */
            details_json: string;
            /** Findings Json */
            findings_json: string;
            /** Raw Output */
            raw_output: string;
            /** Result Id */
            result_id: number;
            /** Truncated */
            truncated: string[];
        };
        /** UpdateUserBody */
        UpdateUserBody: {
            /** Expected Revision */
            expected_revision: number;
            /** Password */
            password?: string | null;
            /**
             * Role
             * @enum {string}
             */
            role: "admin" | "analyst";
        };
        /** UserCreated */
        UserCreated: {
            /** User Id */
            user_id: number;
        };
        /** UserFence */
        UserFence: {
            /** Expected Revision */
            expected_revision: number;
        };
        /** UserPage */
        UserPage: {
            /** Items */
            items: components["schemas"]["UserSummary"][];
            /** Next After */
            next_after: number | null;
        };
        /** UserPayload */
        UserPayload: {
            /** Id */
            id: number;
            /** Role */
            role: string;
            /** Username */
            username: string;
        };
        /** UserSummary */
        UserSummary: {
            /** Auth Source */
            auth_source: string;
            /** Created At */
            created_at: string;
            /** Display Name */
            display_name: string | null;
            /** Id */
            id: number;
            /** Last Login At */
            last_login_at: string | null;
            /** Management Revision */
            management_revision: number;
            /** Role */
            role: string;
            /** Username */
            username: string;
            /** Username Truncated */
            username_truncated: boolean;
        };
        /** WorkerCredentialsRevoked */
        WorkerCredentialsRevoked: {
            /** Node Id */
            node_id: string;
            /** Revoked Count */
            revoked_count: number;
        };
        /** WorkerIdentityBody */
        WorkerIdentityBody: {
            /** Node Id */
            node_id: string;
        };
        /** WorkerLifecycleBody */
        WorkerLifecycleBody: {
            /**
             * Lifecycle State
             * @enum {string}
             */
            lifecycle_state: "active" | "draining" | "disabled";
            /** Node Id */
            node_id: string;
        };
        /** WorkerLifecycleSaved */
        WorkerLifecycleSaved: {
            /** Lifecycle State */
            lifecycle_state: string;
            /** Node Id */
            node_id: string;
        };
        /** WorkerPage */
        WorkerPage: {
            /** Items */
            items: components["schemas"]["WorkerSummary"][];
            /** Next After */
            next_after: string | null;
            /** Stale After Seconds */
            stale_after_seconds: number;
        };
        /** WorkerSummary */
        WorkerSummary: {
            /** Active Scan Id */
            active_scan_id: number | null;
            /** Age Seconds */
            age_seconds: number;
            /** Agent Version */
            agent_version: string;
            /** Capacity */
            capacity: number;
            /** Display Name */
            display_name: string;
            /** Engine Keys */
            engine_keys: string[];
            /** Hostname */
            hostname: string;
            /** Labels */
            labels: {
                [key: string]: string;
            };
            /** Last Heartbeat At */
            last_heartbeat_at: number;
            /** Lifecycle State */
            lifecycle_state: string;
            /** Metadata Incomplete */
            metadata_incomplete: boolean;
            /** Node Id */
            node_id: string;
            /** Online */
            online: boolean;
            /** Platform */
            platform: string;
            /** Runtime State */
            runtime_state: string;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    browser_about_api_ui_v1_about_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AboutPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    own_account_api_ui_v1_account_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AccountPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    change_own_password_api_ui_v1_account_password_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordChangeBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_api_ledger_api_ui_v1_api_ledger_get: {
        parameters: {
            query?: {
                before?: number | null;
                client_id?: number | null;
                limit?: number;
                q?: string;
                risk?: "all" | "pending" | "info" | "metadata_only" | "low" | "medium" | "high" | "critical";
                source?: "all" | "api" | "icap";
                status?: "all" | "active" | "queued" | "running" | "finalizing" | "completed" | "partial" | "failed" | "skipped";
                unassigned?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LedgerPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_batch_api_ui_v1_api_ledger_batches__batch_id__get: {
        parameters: {
            query?: {
                after_created?: string | null;
                after_id?: number | null;
                limit?: number;
            };
            header?: never;
            path: {
                batch_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BatchPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_batch_download_api_ui_v1_api_ledger_batches__batch_id__download_get: {
        parameters: {
            query?: {
                kind?: "status" | "result";
            };
            header?: never;
            path: {
                batch_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Complete public batch contract as a downloadable document */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, never>;
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_batch_json_api_ui_v1_api_ledger_batches__batch_id__json_get: {
        parameters: {
            query?: {
                kind?: "status" | "result";
            };
            header?: never;
            path: {
                batch_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BatchPreview"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    bulk_delete_automation_scans_api_ui_v1_api_ledger_scans_delete: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkDeleteBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkDeleteResult"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_report_api_ui_v1_api_ledger_scans__scan_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanReport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_automation_scan_api_ui_v1_api_ledger_scans__scan_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScanAttemptBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanDeleted"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_automation_archive_children_api_ui_v1_api_ledger_scans__scan_id__children_get: {
        parameters: {
            query?: {
                after?: number | null;
                attempt?: number | null;
                limit?: number;
                q?: string;
                status?: "all" | "active" | "queued" | "running" | "finalizing" | "completed" | "partial" | "failed" | "skipped";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ArchivePage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_full_export_api_ui_v1_api_ledger_scans__scan_id__export_get: {
        parameters: {
            query?: {
                format?: "json" | "csv";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SummaryExport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_printable_report_api_ui_v1_api_ledger_scans__scan_id__print_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PrintableReport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_result_json_api_ui_v1_api_ledger_scans__scan_id__result_json_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResultPreview"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_technical_api_ui_v1_api_ledger_scans__scan_id__results__result_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TechnicalDetails"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_full_output_api_ui_v1_api_ledger_scans__scan_id__results__result_id__full_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FullTechnicalDetails"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_result_output_api_ui_v1_api_ledger_scans__scan_id__results__result_id__output_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/plain": string;
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_status_json_api_ui_v1_api_ledger_scans__scan_id__status_json_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResultPreview"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    automation_summary_export_api_ui_v1_api_ledger_scans__scan_id__summary_export_get: {
        parameters: {
            query?: {
                format?: "json" | "csv";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SummaryExport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_audit_api_ui_v1_audit_get: {
        parameters: {
            query?: {
                before?: number | null;
                limit?: number;
                outcome?: "all" | "success" | "failure" | "denied";
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_manual_batch_api_ui_v1_batches__batch_id__get: {
        parameters: {
            query?: {
                after_created?: string | null;
                after_id?: number | null;
                limit?: number;
            };
            header?: never;
            path: {
                batch_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BatchPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    dashboard_scans_api_ui_v1_dashboard_scans_get: {
        parameters: {
            query?: {
                before?: number | null;
                limit?: number;
                q?: string;
                risk?: "all" | "pending" | "info" | "low" | "medium" | "high" | "critical";
                status?: "all" | "active" | "queued" | "running" | "finalizing" | "completed" | "partial" | "failed";
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    dashboard_summary_api_ui_v1_dashboard_summary_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DashboardSummary"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    engines_api_ui_v1_engines_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InventoryPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    create_engine_api_ui_v1_engines_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstanceSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_engine_api_ui_v1_engines__instance_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    check_engine_api_ui_v1_engines__instance_id__checks_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthPayload"];
                };
            };
            /** @description Worker check requested; not a successful connection. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    configure_engine_api_ui_v1_engines__instance_id__config_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ConfigBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstanceSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    enable_engine_api_ui_v1_engines__instance_id__enabled_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnabledBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstanceEnabled"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    placement_api_ui_v1_engines__instance_id__placement_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PlacementBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstanceSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    rules_api_ui_v1_engines__instance_id__rules_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RulesPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    upload_rule_api_ui_v1_engines__instance_id__rules_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RuleBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuleSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_rule_api_ui_v1_engines__instance_id__rules__name__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
                name: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    toggle_rule_api_ui_v1_engines__instance_id__rules__name__toggle_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: number;
                name: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RuleSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_hash_list_api_ui_v1_hash_list_get: {
        parameters: {
            query?: {
                before?: number | null;
                kind?: "all" | "block" | "allow";
                limit?: number;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HashListPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_add_hashes_api_ui_v1_hash_list_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AddHashesBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HashesAdded"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_remove_hash_api_ui_v1_hash_list__entry_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                entry_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_hash_lookup_api_ui_v1_hash_scan_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HashLookupBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HashLookupResult"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_hash_lookup_options_api_ui_v1_hash_scan_options_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HashLookupOptions"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_browser_scan_policy_api_ui_v1_scan_policy_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanPolicySnapshot"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    save_browser_scan_policy_api_ui_v1_scan_policy_put: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScanPolicyBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    submit_scan_api_ui_v1_scans_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "multipart/form-data": components["schemas"]["Body_submit_scan_api_ui_v1_scans_post"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubmissionAccepted"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    bulk_delete_manual_scans_api_ui_v1_scans_delete: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkDeleteBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkDeleteResult"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_scan_report_api_ui_v1_scans__scan_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanReport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_manual_scan_api_ui_v1_scans__scan_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScanAttemptBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanDeleted"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_archive_children_api_ui_v1_scans__scan_id__children_get: {
        parameters: {
            query?: {
                after?: number | null;
                attempt?: number | null;
                limit?: number;
                q?: string;
                status?: "all" | "active" | "queued" | "running" | "finalizing" | "completed" | "partial" | "failed" | "skipped";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ArchivePage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    export_scan_full_api_ui_v1_scans__scan_id__export_get: {
        parameters: {
            query?: {
                format?: "json" | "csv";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SummaryExport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    manual_printable_report_api_ui_v1_scans__scan_id__print_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PrintableReport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_scan_technical_details_api_ui_v1_scans__scan_id__results__result_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TechnicalDetails"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_full_engine_output_api_ui_v1_scans__scan_id__results__result_id__full_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FullTechnicalDetails"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    manual_result_output_api_ui_v1_scans__scan_id__results__result_id__output_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: number;
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/plain": string;
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                    "text/plain": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    retry_manual_scan_api_ui_v1_scans__scan_id__retry_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScanAttemptBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RetryAccepted"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    export_scan_summary_api_ui_v1_scans__scan_id__summary_export_get: {
        parameters: {
            query?: {
                format?: "json" | "csv";
            };
            header?: never;
            path: {
                scan_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SummaryExport"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    submission_options_api_ui_v1_scans_options_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubmissionOptions"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_browser_service_clients_api_ui_v1_service_clients_get: {
        parameters: {
            query?: {
                after?: number | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceClientPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_create_client_api_ui_v1_service_clients_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ClientCreateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientCreated"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    update_browser_service_client_api_ui_v1_service_clients__client_id__put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ServiceClientUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_credentials_api_ui_v1_service_clients__client_id__credentials_get: {
        parameters: {
            query?: {
                after?: number | null;
            };
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CredentialPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_create_credential_api_ui_v1_service_clients__client_id__credentials_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CredentialBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CredentialCreated"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_revoke_credential_api_ui_v1_service_clients__client_id__credentials__credential_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
                credential_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_browser_profiles_api_ui_v1_service_clients__client_id__profiles_get: {
        parameters: {
            query?: {
                after?: number | null;
            };
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientProfiles"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    create_browser_profile_api_ui_v1_service_clients__client_id__profiles_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileCreateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProfileCreated"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    update_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
                profile_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileUpdateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
                profile_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileFence"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    default_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__default_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
                profile_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileDefaultBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    save_browser_profile_api_ui_v1_service_clients__client_id__profiles__profile_id__engines_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
                profile_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProfileRoutingBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_client_readiness_api_ui_v1_service_clients__client_id__readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientReadiness"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_browser_client_storage_api_ui_v1_service_clients__client_id__storage_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientStorageAccess"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    save_browser_client_storage_api_ui_v1_service_clients__client_id__storage_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                client_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StorageAccessUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_client_create_options_api_ui_v1_service_clients_create_options_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientCreateOptions"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    session_api_ui_v1_session_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SessionPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    sign_in_api_ui_v1_session_login_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["LoginBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SessionPayload"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    sign_out_api_ui_v1_session_logout_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_engine_metrics_api_ui_v1_system_engine_metrics_get: {
        parameters: {
            query?: {
                after?: number | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EngineMetricPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_worker_pools_api_ui_v1_system_pools_get: {
        parameters: {
            query?: {
                after?: number | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PoolPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    create_browser_pool_api_ui_v1_system_pools_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PoolCreateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PoolSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    update_browser_pool_api_ui_v1_system_pools__pool_id__put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                pool_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PoolUpdateBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PoolSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    delete_browser_pool_api_ui_v1_system_pools__pool_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                pool_id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_active_queue_api_ui_v1_system_queue_get: {
        parameters: {
            query?: {
                after?: number | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActiveQueuePage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_retention_candidates_api_ui_v1_system_retention_get: {
        parameters: {
            query?: {
                after?: number | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RetentionPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    run_browser_retention_api_ui_v1_system_retention_run_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RetentionRunBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkDeleteResult"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_system_summary_api_ui_v1_system_summary_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemSummary"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    read_system_workers_api_ui_v1_system_workers_get: {
        parameters: {
            query?: {
                after?: string | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    revoke_worker_credentials_api_ui_v1_system_workers_credentials_revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WorkerIdentityBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerCredentialsRevoked"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    change_worker_lifecycle_api_ui_v1_system_workers_lifecycle_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WorkerLifecycleBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerLifecycleSaved"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_users_api_ui_v1_users_get: {
        parameters: {
            query?: {
                after?: number | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserPage"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_create_user_api_ui_v1_users_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateUserBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserCreated"];
                };
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_update_user_api_ui_v1_users__user_id__put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["UpdateUserBody"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
    browser_delete_user_api_ui_v1_users__user_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserFence"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad Request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Not Found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Conflict */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Content Too Large */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Unprocessable Content */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorPayload"];
                };
            };
        };
    };
}
