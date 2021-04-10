"""
Prompt for apikey
Prompt for hash
Request hash report from VT
Parse only non-clean detections- AV name, detection name, version/definitions, VT updated date
Print above info
"""

import requests,time,csv
from time import sleep


# requests setup
requests.urllib3.disable_warnings()
client =  requests.session()
client.verify = False

apikey = '5c0d67f571ebd3d0404de3d3db093e76c5d49fca528d5fe8c38c0dbc8db43f6f' #Enter your API key.')


def get_hash_report(apikey, filehash , val):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {"apikey": apikey, "resource": filehash, "allinfo": True}

    # perform call
    r = client.get(url, params=params)

    if r.status_code == 429:
        print('Encountered rate-limiting. Sleeping for 45 seconds.')
        sleep(45)
        get_hash_report(apikey, filehash)

    elif r.status_code != 200:
        print('Encountered unanticipated HTTP error.')
        print(r.status_code)
        exit(1)

    elif r.status_code == 200:
        response = r.json()
        parse_hash_report(response,filehash,val)


def parse_hash_report(response, filehash, val):
    detections = response['positives']
    total = response['total']
    if detections >= 1:
        scan_results = response['scans']
        x = 0
        for vendor in scan_results:
            if scan_results[vendor]['detected'] == True and x ==0 :
                print ("malicious detected")
                info_date = scan_results[vendor]['update']
                detected_name = scan_results[vendor]['result']
                definition_version = scan_results[vendor]['version']
                with open('/home/radius/analisis-tools/report.csv','a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([val,filehash,vendor,detected_name,"{} Engine dari {}".format(detections,total)])
                x += 1
            break

    else:
        print('No malicious detections found.')
    while True:
        time.sleep(20)
        return


if __name__ == "__main__":
    d = {}
    with open("/home/radius/analisis-tools/hash.txt","r") as f:
        for line in f:
            (key, val) = line.split()
            d[val] = key
    for x , y in d.items():
        get_hash_report(apikey, x, y)
