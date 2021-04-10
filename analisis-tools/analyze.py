import subprocess
import os
import sys
import hashlib

pcap_master= "/home/radius/analisis-tools/pcap-master/"
export_dir = "/home/radius/analisis-tools/export_dir/"
def export():
    entries = os.listdir(pcap_master)
    for entry in entries:
        proc = subprocess.call("tshark -Q -r {} --export-objects http,{}".format(entry, export_dir),shell=True)
    
def get_hash():
    def hash_file(fdir,fname):
        BUF_SIZE = 1024
        sha1 = hashlib.sha1()
        with open(fdir, "rb") as f:
            chunk = 0
            while chunk != b'':
                chunk = f.read(BUF_SIZE)
                sha1.update(chunk)
                #print("MD5 : {0}".format(sha1.hexdigest()))
        fhash = open("/home/radius/analisis-tools/hash.txt", "a")
        fhash.write("{} | {}\n".format(fname,sha1.hexdigest()))
        fhash.close()

    files = os.listdir(export_dir)
    for myfile in files:
        y = os.listdir(export_dir+myfile)
        for x in y:
            myhash = hash_file(export_dir+myfile+"/"+x, myfile)
        
        
if __name__ == "__main__":
    get_hash()


