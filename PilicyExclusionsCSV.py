import requests
import pandas as pd

def get_list_names(list_ids, url, headers):
    list_names = []
    for list_id in list_ids:
        response = requests.get(f"{url}/{list_id}", headers=headers)
        if response.status_code == 200:
            list_names.append(response.json().get('name', ''))
        else:
            list_names.append(str(list_id))  
    return ", ".join(list_names)

def get_policy_details(region, api_key):
    url = f"https://workload.{region}.cloudone.trendmicro.com/api/policies"
    headers = {
        'Authorization': f'ApiKey {api_key}',
        'api-version': 'v1',
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()

region = input("Enter your region: ")
api_key = input("Enter your C1 API key: ")
policy_details = get_policy_details(region, api_key)

filtered_policies = [policy for policy in policy_details['policies'] 
                     if any(sub_string in policy['name'] for sub_string in ['qas-WinSvr', 'dev-WinSvr', 'prd-WinSvr'])]

exclusions_data = []
headers = {
  'Authorization': f'ApiKey {api_key}',
  'api-version': 'v1',
  'Content-Type': 'application/json'
}
base_url = f"https://workload.{region}.cloudone.trendmicro.com/api"

for policy in filtered_policies:
    policy_name = policy['name']
    anti_malware_settings = policy['antiMalware']

    exclusions_data.append({
        'Policy Name': policy_name,
        'Real Time Scan - Directory Lists': get_list_names(anti_malware_settings['realTimeScanExcludedDirectorySetting']['directoryLists'], f"{base_url}/directorylists", headers),
        'Real Time Scan - File Extension Lists': get_list_names(anti_malware_settings['realTimeScanExcludedFileExtensionSetting']['fileExtensionLists'], f"{base_url}/fileextensionlists", headers),
        'Real Time Scan - File Lists': get_list_names(anti_malware_settings['realTimeScanExcludedFileSetting']['fileLists'], f"{base_url}/filelists", headers),
        'Manual Scan - Directory Lists': get_list_names(anti_malware_settings['manualScanExcludedDirectorySetting']['directoryLists'], f"{base_url}/directorylists", headers),
        'Manual Scan - File Extension Lists': get_list_names(anti_malware_settings['manualScanExcludedFileExtensionSetting']['fileExtensionLists'], f"{base_url}/fileextensionlists", headers),
        'Manual Scan - File Lists': get_list_names(anti_malware_settings['manualExcludedScanFileSetting']['fileLists'], f"{base_url}/filelists", headers),
        'Scheduled Scan - Directory Lists': get_list_names(anti_malware_settings['scheduledScanExcludedDirectorySetting']['directoryLists'], f"{base_url}/directorylists", headers),
        'Scheduled Scan - File Extension Lists': get_list_names(anti_malware_settings['scheduledScanExcludedFileExtensionSetting']['fileExtensionLists'], f"{base_url}/fileextensionlists", headers),
        'Scheduled Scan - File Lists': get_list_names(anti_malware_settings['scheduledScanExcludedFileSetting']['fileLists'], f"{base_url}/filelists", headers)
    })

exclusions_df = pd.DataFrame(exclusions_data)
exclusions_df.to_csv('exclusions.csv', index=False)
