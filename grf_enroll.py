"""Open self-service signup. Private credentials are generated on this computer."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time
import uuid

DEFAULT_HOST = 'grf-authority.politecoast-1d7eef92.eastus.azurecontainerapps.io'


def protect(folder):
    if os.name=='nt':
        who=subprocess.run(['whoami'],capture_output=True,text=True,check=True).stdout.strip()
        subprocess.run(['icacls',str(folder),'/inheritance:r','/grant:r',who+':(OI)(CI)F',
                        'SYSTEM:(OI)(CI)F'],capture_output=True,check=True)
        script='''$ErrorActionPreference='Stop'
$ownerSid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=Get-Acl -LiteralPath $env:GRF_PRIVATE_DIR
foreach($rule in $acl.Access) {
 $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
 if($rule.AccessControlType -eq 'Allow' -and $sid -ne $ownerSid.Value -and $sid -notin @('S-1-5-18','S-1-5-32-544','S-1-3-4')) {
  throw 'Existing custom permissions allow another identity; use a new private project directory.'
 }
}
'''
        subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',script],
                       env={**os.environ,'GRF_PRIVATE_DIR':str(folder)},capture_output=True,check=True)
    else:
        folder.chmod(0o700)


def request(host,path,value,account=None,secret=None):
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,250}',host): raise ValueError('Invalid HTTPS host')
    raw=json.dumps(value,separators=(',',':')).encode()
    headers={'Content-Type':'application/json'}
    if account and secret: headers.update(Authorization='Bearer '+secret,**{'X-GRF-Account':account})
    for attempt in range(4):
        c=http.client.HTTPSConnection(host,443,context=ssl.create_default_context(),timeout=15)
        try:
            c.request('POST',path,raw,headers)
            response=c.getresponse();body=response.read(8193)
            if response.status==429 and attempt<3:
                time.sleep(5*(attempt+1));continue
            if response.status!=200 or len(body)>8192: raise ValueError('Enrollment unavailable or denied; retry later')
            value=json.loads(body)
            if not isinstance(value,dict) or value.get('allowed') is not True: raise ValueError('Enrollment denied')
            return value
        finally: c.close()
    raise ValueError('Enrollment busy; retry later')


def enroll(project,host=DEFAULT_HOST):
    project=Path(project).resolve()
    document=project/'project.grf'
    if not document.is_file(): raise ValueError('Initialize a GRF project first')
    text=document.read_text(encoding='utf-8')
    header='```grf:context id="downstream-project"\n'
    if not text.startswith(header) or not text.endswith('\n```\n'): raise ValueError('Invalid project document')
    doc=json.loads(text[len(header):-5])
    folder=project/'credentials'
    if folder.is_symlink(): raise ValueError('Credentials directory cannot be a symlink')
    folder.mkdir(mode=0o700,exist_ok=True)
    protect(folder)
    credential=folder/'access.key'
    pending=folder/'signup.json'
    config_path=folder/'enrollment.json'
    if any(p.is_symlink() for p in (credential,pending,config_path)):
        raise ValueError('Credential files cannot be symlinks')
    if config_path.exists():
        config=json.loads(config_path.read_text())
        if config.get('transport')!='public-https' or config['host']!=host:
            raise ValueError('Existing enrollment preserved; use a separate project')
        secret=credential.read_text(encoding='ascii').strip()
        account=config['account']
        response=request(host,'/v1/renew',{},account,secret)
    else:
        if pending.exists():
            saved=json.loads(pending.read_text());account=saved['account']
            if saved['host']!=host: raise ValueError('Pending signup belongs to another host')
            secret=credential.read_text(encoding='ascii').strip()
        else:
            if credential.exists(): raise ValueError('Existing credential preserved')
            secret=secrets.token_urlsafe(32);account=uuid.uuid4().hex
            with credential.open('x',encoding='ascii') as stream: stream.write(secret)
            credential.chmod(0o600)
            pending.write_text(json.dumps({'account':account,'host':host}))
            pending.chmod(0o600)
        response=request(host,'/v1/enroll',{'account':account,'credential_hash':hashlib.sha256(secret.encode()).hexdigest()})
    if (response.get('account')!=account or response.get('project')!='public-'+account
            or response.get('policy')!='public-1' or type(response.get('expires')) is not int
            or response['expires']<=time.time()): raise ValueError('Invalid enrollment response')
    config={'host':host,'port':443,'transport':'public-https','account':account,
            'project':response['project'],'policy':'public-1','credential_file':'access.key','expires':response['expires']}
    temp=folder/('enrollment-'+uuid.uuid4().hex+'.tmp')
    temp.write_text(json.dumps(config,indent=2));temp.chmod(0o600);os.replace(temp,config_path)
    ignore=project/'.gitignore'
    prior=ignore.read_text() if ignore.exists() else ''
    if '/credentials/' not in prior.splitlines(): ignore.write_text(prior.rstrip()+'\n/credentials/\n')
    doc['admission']={'mode':'remote','enrollment':'credentials/enrollment.json'}
    replacement=project/('project-'+uuid.uuid4().hex+'.tmp')
    replacement.write_text(header+json.dumps(doc,indent=2)+'\n```\n',encoding='utf-8')
    os.replace(replacement,document)
    return {'enrolled':True,'project':str(project),'credentials':'credentials/enrollment.json',
            'access':'Open cooperative cloud admission; local checks stay local.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',help='Existing project directory created by grf_starter.py init')
    parser.add_argument('--host',default=DEFAULT_HOST,help='Verified HTTPS service hostname')
    args=parser.parse_args()
    try: print(json.dumps(enroll(args.project,args.host),indent=2))
    except Exception as error:
        # Exception details from networking may contain sensitive configuration.
        raise SystemExit('Enrollment did not finish ('+type(error).__name__+'). Existing credentials preserved; rerun to retry.') from None


if __name__=='__main__': main()
