"""Check every public Go SDK operation and documented option at the HTTP boundary.

Requires Python with PyYAML and Go. No network requests are made: a Go
RoundTripper captures requests before they reach a socket. Synthetic parameter
values prove serialization, not acceptance by a running API.
"""
import argparse
import json
import pathlib
import re
import subprocess
import tempfile
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--openapi', type=pathlib.Path, default=ROOT.parents[1] / 'docs-site/openapi.yaml')
parser.add_argument('--output', type=pathlib.Path)
args = parser.parse_args()
spec = yaml.safe_load(args.openapi.read_text())
source = '\n'.join(p.read_text() for p in (ROOT / 'pkg/oathnet').glob('*.go') if not p.name.endswith('_test.go'))

def resolve(value):
    while '$ref' in value:
        ref = value['$ref']
        value = spec
        for part in ref[2:].split('/'): value = value[part]
    return value

def sample(value):
    value = resolve(value)
    if 'enum' in value: return next(v for v in value['enum'] if v is not None)
    if 'anyOf' in value or 'oneOf' in value:
        return sample(next(v for v in value.get('anyOf', value.get('oneOf')) if v.get('type') != 'null'))
    kind = value.get('type', 'object')
    if isinstance(kind, list): kind = next(v for v in kind if v != 'null')
    if kind == 'array': return [sample(value.get('items', {'type':'string'}))]
    if kind == 'object': return {k: sample(v) for k, v in value.get('properties',{}).items() if k in value.get('required',[])}
    if kind == 'integer': return max(1, value.get('minimum',0))
    if kind == 'number': return max(0.5, value.get('minimum',0))
    if kind == 'boolean': return False
    if value.get('format') == 'uuid': return '00000000-0000-4000-8000-000000000001'
    if value.get('format') == 'uri': return 'https://example.com/notify'
    return 'example'

def fields(name):
    alias = re.search(r'type '+re.escape(name)+r' = (\w+)', source)
    if alias: return fields(alias[1])
    match = re.search(r'type '+re.escape(name)+r' struct \{\n(.*?)^\}',source,re.M|re.S)
    if not match: raise ValueError('missing Go struct '+name)
    result = {}
    for line in match[1].splitlines():
        line = line.split('//')[0].strip()
        match = re.match(r'(\w+)\s+([^`]+?)(?:\s+`json:"([^",]+)[^`]*`)?$',line)
        if match: result[match[1]] = (match[2].strip(),match[3])
    return result

def literal(value,kind='interface{}'):
    if kind.startswith('*'): return 'pointer('+literal(value,kind[1:])+')'
    if value is None: return 'nil'
    if kind.startswith('[]'):
        return kind.replace('[]V2','[]oathnet.V2')+'{'+','.join(literal(v,kind[2:]) for v in value)+'}'
    if isinstance(value,dict):
        map_type=kind
        if kind in ('interface{}','any'): map_type='map[string]interface{}'
        elif not kind.startswith('map['): map_type='oathnet.'+kind
        value_type='interface{}'
        if kind.startswith('map[string]'): value_type=kind[len('map[string]'):]
        # Named request maps have precise child types.
        if kind=='V2InvestigationSectionFilters': value_type='map[string]interface{}'
        if kind=='V2InvestigationCursors': value_type='*string'
        return map_type+'{'+','.join(json.dumps(k)+':'+literal(v,value_type) for k,v in value.items())+'}'
    if isinstance(value,list):
        if all(isinstance(v,str) for v in value): return '[]string{'+','.join(json.dumps(v) for v in value)+'}'
        return '[]interface{}{'+','.join(literal(v) for v in value)+'}'
    if isinstance(value,bool): return str(value).lower()
    if isinstance(value,(int,float)): return str(value)
    if kind not in ('string','interface{}','any'):
        if kind.startswith('AIFilter'): return 'oathnet.'+kind+'('+json.dumps(value)+')'
    return json.dumps(value)

ALIASES={
'q':['Query','Q'],'from':['From'],'to':['To'],'type':['Type'],
'fields':['Fields'],'email':['Email','Emails'],'email_domain':['EmailDomains'],
'domain':['Domains','Domain'],'subdomain':['Subdomains','Subdomain'],'username':['Usernames','Username'],
'password':['Passwords','Password'],'password_hash':['PasswordHashes'],'path':['Paths'],
'ip':['IPs','IP'],'phone':['Phones'],'first_name':['FirstNames'],'last_name':['LastNames'],
'full_name':['FullNames'],'city':['Cities','City'],'country':['Countries','Country'],'state':['States'],
'postal_code':['PostalCodes'],'dbname':['DBNames'],'discord_id':['DiscordIDs','DiscordID'],
'iban':['IBANs'],'ssn':['SSNs'],'name':['Names','Name'],'gender':['Genders'],'address':['Addresses'],
'hwid':['HWIDs'],'source_type':['SourceTypes','SourceType'],'archive_hash':['ArchiveHashes'],
'canonical_credential_id':['CanonicalCredentialIDs'],'os':['OSes','OS'],'service':['Services','Service'],
'steam_id':['SteamIDs'],'steam_name':['SteamNames'],'identity_state':['IdentityStates'],
'victim_ip':['VictimIPs'],'infection_path':['InfectionPaths'],'filter_id':['FilterID'],
'search_id':['SearchID'],'log_id':['LogID'],'job_id':['JobID'],'user_id':['UserID'],'log_ids':['LogIDs'],
'dbnames':['DBNames','DBNameList'],'query_config':['QueryConfig'],'search_type':['SearchType'],
'include_info':['IncludeInfo'],'scanner_type':['ScannerType'],
'destination_uid':['DestinationUID'],'webhook_url':['WebhookURL'],
'source_file_id':['SourceFileID'],'file_id':['FileID'],
}

def struct_value(name,values):
    definitions=fields(name)
    values=dict(values)
    assignments={}
    extra={}
    for key,value in values.items():
        candidates=[n for n,(_,tag) in definitions.items() if tag==key]+ALIASES.get(key,[])
        camel=''.join(part.capitalize() for part in key.split('_'))
        candidates += [camel,camel+'s']
        if key=='alive' and 'AliveValue' in definitions: candidates.insert(0,'AliveValue')
        if key=='is_alive' and 'IsAliveValue' in definitions: candidates.insert(0,'IsAliveValue')
        candidates=[n for n in candidates if n in definitions]
        if isinstance(value,list):
            candidates.sort(key=lambda n: 0 if definitions[n][0].startswith('[]') else 1)
        if not candidates:
            if 'ExtraQuery' in definitions:
                extra[key]=value
                continue
            raise ValueError(name+' has no field for '+key)
        field=candidates[0];kind=definitions[field][0]
        # Existing value-bool query options cannot distinguish false from omit.
        # Their public ExtraQuery escape hatch preserves an explicit false.
        if value is False and kind=='bool' and 'Extra' in definitions:
            assignments.setdefault('Extra','')
            extra[key]=value
            continue
        if value is False and kind=='bool' and 'ExtraQuery' in definitions:
            extra[key]=value
            continue
        assignments[field]=literal(value,kind)
    if extra and 'ExtraQuery' not in definitions:
        assignments['Extra']=literal(extra)
        extra={}
    if extra:
        encoded={k: ([str(v).lower() if isinstance(v,bool) else str(v) for v in value] if isinstance(value,list) else [str(value).lower() if isinstance(value,bool) else json.dumps(value,separators=(',',':')) if isinstance(value,dict) else str(value)]) for k,value in extra.items()}
        assignments['ExtraQuery']='map[string][]string{'+','.join(json.dumps(k)+':'+literal(v,'[]string') for k,v in encoded.items())+'}'
    return '&oathnet.'+name+'{'+','.join(k+':'+v for k,v in assignments.items())+'}'

# Each entry chooses the public service method and the corresponding option type.
GET={
'searchBreach':('Search.Breach','q','SearchOptions'),'searchStealerOriginal':('Search.Stealer','q','SearchOptions'),
'searchBreachV2':('Breach.SearchGet','q','BreachV2SearchOptions'),'searchStealerV2':('Stealer.SearchGet','q','StealerSearchOptions'),'searchVictimsV2':('Victims.SearchGet','q','VictimsSearchOptions'),
'investigateStealerV2':('Stealer.InvestigationSearch','q','InvestigationSearchOptions'),
'extractSubdomainV2':('Stealer.ExtractSubdomainV2','domain','SubdomainOptions'),'getPhonebookV2':('Stealer.GetPhonebook','domain','PhonebookOptions'),
'autocompleteBreachValuesV2':('Breach.Autocomplete',None,'BreachV2AutocompleteOptions'),'autocompleteBreachDBNamesV2':('Breach.AutocompleteDBNames',None,'BreachV2AutocompleteDBNamesOptions'),'autocompleteBreachFieldsV2':('Breach.AutocompleteFields',None,'BreachV2AutocompleteFieldsOptions'),
'searchFilesMetadataV2':('Victims.SearchFilesMetadata',None,'FileMetadataSearchOptions'),'searchVictimPropertiesV2':('Victims.SearchVictimProperties',None,'VictimPropertiesSearchOptions'),
'getVictimPropertiesV2':('Victims.GetProperties','log_id','VictimPropertiesSearchOptions'),'getVictimSummaryV2':('Victims.GetSummary','log_id','VictimSummaryOptions'),'getVictimCookiesV2':('Victims.GetCookies','log_id','VictimCookieInventoryOptions'),'inspectVictimCookieDomainV2':('Victims.InspectCookieDomain','log_id','VictimCookieDomainOptions'),
'getVictimManifestV2':('Victims.GetManifest','log_id','VictimRawOptions'),'downloadVictimArchiveV2':('Victims.DownloadArchiveBytes','log_id','VictimRawOptions'),
'listScanners':('Scanners.List',None,'ScannerListOptions'),'listScannerRuns':('Scanners.ListRuns','scanner_uid','ScannerRunsOptions'),
}
POST={
'investigateStealerV2Post':('Stealer.InvestigationSearchPost','V2InvestigationSearchRequest',True),
'searchFilesMetadataV2Post':('Victims.SearchFilesMetadataPost','V2FileMetadataSearchRequest',True),'searchVictimPropertiesV2Post':('Victims.SearchVictimPropertiesPost','V2VictimPropertiesSearchRequest',True),
'createAIFilterV2':('AI.Create','V2AIFilterRequest',False),
'createScanner':('Scanners.Create','ScannerCreateRequest',False),'updateScanner':('Scanners.Update','ScannerUpdateRequest',False),'testDraftScannerDelivery':('Scanners.TestDraftDelivery','ScannerDraftTestRequest',False),
'createScannerDestination':('Scanners.CreateDestination','ScannerDestinationCreateRequest',False),
'enrichIdentity':('OSINT.EnrichIdentity','EnrichmentRequest',False),'enrichIdentityPost':('OSINT.EnrichIdentityPost','EnrichmentRequest',False),
}
SIMPLE={
'getAIFilterContextV2':('AI.GetContext',['filter_id']),'getFileSearchV2':('FileSearch.GetStatus',['job_id']),'getBulkSearchV2':('Bulk.GetStatus',['job_id']),'downloadBulkSearchV2':('Bulk.DownloadBytes',['job_id']),'getExportV2':('Exports.GetStatus',['job_id']),'downloadExportV2':('Exports.DownloadBytes',['job_id']),
'getScannerQuota':('Scanners.GetQuota',[]),'getScanner':('Scanners.Get',['scanner_uid']),'deleteScanner':('Scanners.Delete',['scanner_uid']),'testScannerNotification':('Scanners.TestNotification',['scanner_uid']),'getScannerWebhookSecurity':('Scanners.GetWebhookSecurity',['scanner_uid']),'rotateScannerWebhookSecret':('Scanners.RotateWebhookSecret',['scanner_uid']),'pauseScanner':('Scanners.Pause',['scanner_uid']),'resumeScanner':('Scanners.Resume',['scanner_uid']),'triggerScanner':('Scanners.Trigger',['scanner_uid']),'getScannerRun':('Scanners.GetRun',['scanner_uid','run_uid']),
'listScannerDestinations':('Scanners.ListDestinations',[]),'deleteScannerDestination':('Scanners.DeleteDestination',['destination_uid']),
'listBulkSearchV2':('Bulk.List',['page','page_size']),'listExportsV2':('Exports.List',['page','page_size']),'dbnameAutocomplete':('Utility.DBNameAutocomplete',['q']),
}
OSINT={
'ipInfo':('IPInfo','ip'),'steamLookup':('Steam','steam_id'),'xboxLookup':('Xbox','xbl_id'),'discordUserinfo':('DiscordUserinfo','discord_id'),'discordUsernameHistory':('DiscordUsernameHistory','discord_id'),'holehe':('Holehe','email'),'ghunt':('GHunt','email'),'minecraftHistory':('MinecraftHistory','username')}

def call(opid,arguments):
    arguments=dict(arguments)
    if opid in GET:
        method,first,opts=GET[opid];parts=[]
        if first: parts.append(literal(arguments.pop(first)))
        parts.append(struct_value(opts,arguments));return method,parts
    if opid in POST:
        method,kind,pointer=POST[opid];parts=[]
        if opid=='updateScanner': parts.append(literal(arguments.pop('scanner_uid')))
        value=struct_value(kind,arguments)
        parts.append(value if pointer else value.removeprefix('&'))
        return method,parts
    if opid in SIMPLE:
        method,keys=SIMPLE[opid];return method,[literal(arguments.pop(k)) for k in keys]
    if opid in OSINT:
        method,key=OSINT[opid];first=literal(arguments.pop(key))
        return 'OSINT.'+method,[first,struct_value('OSINTOptions',arguments).removeprefix('&')]
    if opid=='robloxUserinfo':return 'OSINT.RobloxUserinfo',[struct_value('RobloxUserinfoOptions',arguments).removeprefix('&')]
    if opid=='extractSubdomain':
        domain=literal(arguments.pop('domain'));alive=literal(arguments.pop('is_alive'),'*bool')
        return 'OSINT.ExtractSubdomain',[domain,alive,struct_value('OSINTOptions',arguments).removeprefix('&')]
    if opid=='getVictimFileV2':
        parts=[literal(arguments.pop(k)) for k in ('log_id','file_id')]
        return 'Victims.GetFile',parts+[struct_value('VictimRawOptions',arguments)]
    if opid in ('searchBreachV2Post','searchStealerV2Post','searchVictimsV2Post'):
        service={'searchBreachV2Post':'Breach','searchStealerV2Post':'Stealer','searchVictimsV2Post':'Victims'}[opid]
        return service+'.SearchPost',[literal(arguments,'V2SearchPostBody'),'nil']
    if opid=='initSearchSession':return 'Search.InitSession',[literal(arguments.pop('query')),struct_value('SearchSessionOptions',arguments)]
    if opid=='createFileSearchV2':return 'FileSearch.Create',[literal(arguments.pop('expression')),struct_value('FileSearchCreateOptions',arguments)]
    if opid=='createExportV2':return 'Exports.Create',[literal(arguments.pop('type')),struct_value('ExportCreateOptions',arguments)]
    if opid=='createBulkSearchV2':return 'Bulk.Create',[literal(arguments.pop('terms'),'[]string'),literal(arguments.pop('service')),struct_value('BulkCreateOptions',arguments)]
    raise ValueError('no method map for '+opid)

rows=[];cases=[]
for path,items in spec['paths'].items():
    for verb,op in items.items():
        if verb not in ('get','post','patch','delete'):continue
        values={};path_fields={};expected={}
        for parameter in op.get('parameters',[]):
            parameter=resolve(parameter);name=parameter['name'];value=sample(parameter.get('schema',{}))
            values[name]=value
            (path_fields if parameter['in']=='path' else expected)[name]=value
        schema=resolve(op.get('requestBody',{}).get('content',{}).get('application/json',{}).get('schema',{}))
        for name,prop in schema.get('properties',{}).items(): values[name]=expected[name]=sample(prop)
        opid=op['operationId']
        try: method,parts=call(opid,values)
        except Exception as exc:
            rows.append({'operation':opid,'error':str(exc)});continue
        wantpath=path
        for key,value in path_fields.items():wantpath=wantpath.replace('{'+key+'}',str(value))
        invocation='c.'+method+'('+','.join(parts)+')'
        invocation=('return '+invocation if verb=='delete' else '_, err := '+invocation+'; return err')
        meta=json.dumps({'operation':opid,'method':method,'parameters':len(expected)+len(path_fields),'path':wantpath,'verb':verb.upper(),'expected':expected},separators=(',',':'))
        cases.append('{meta:'+json.dumps(meta)+',call:func(c *oathnet.Client) error {'+invocation+'}},')

GO_HEADER='''package main
import (
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "os"
 "reflect"
 "strings"
 "github.com/oathnet/oathnet-go/pkg/oathnet"
)
type captureTransport struct { request *http.Request; body []byte }
func (t *captureTransport) RoundTrip(r *http.Request) (*http.Response,error) { t.request=r; if r.Body!=nil { t.body,_=io.ReadAll(r.Body) }; return nil,fmt.Errorf("captured locally") }
func pointer[T any](value T) *T { return &value }
func main(){
 cases:=[]struct{meta string;call func(*oathnet.Client)error}{
'''
GO_FOOTER='''}
 var rows []map[string]interface{}
 for _,tc:=range cases {
  var row map[string]interface{}
  if err:=json.Unmarshal([]byte(tc.meta),&row);err!=nil { panic(err) }
  transport:=&captureTransport{}
  client,err:=oathnet.NewClient("test-placeholder",oathnet.WithBaseURL("https://api.example.test/api"),oathnet.WithHTTPClient(&http.Client{Transport:transport}))
  if err!=nil { panic(err) }; err=tc.call(client)
  if transport.request==nil { row["error"]=fmt.Sprint(err);rows=append(rows,row);continue }
  r:=transport.request
  row["path_ok"]=strings.TrimPrefix(r.URL.Path,"/api")==row["path"]
  row["verb_ok"]=r.Method==row["verb"]
  row["auth_ok"]=r.Header.Get("x-api-key")=="test-placeholder"
  expected:=row["expected"].(map[string]interface{})
  var body map[string]interface{}
  if len(transport.body)>0 { if err:=json.Unmarshal(transport.body,&body);err!=nil { row["error"]=err.Error() } }
  missing:=[]string{};changed:=[]string{}
  for key,want:=range expected {
   if actual,ok:=body[key];ok { if !reflect.DeepEqual(actual,want) {changed=append(changed,key)};continue }
   query,ok:=r.URL.Query()[key]
   if !ok {missing=append(missing,key);continue}
   if arr,ok:=want.([]interface{});ok { converted:=[]interface{}{};for _,v:=range query{converted=append(converted,v)};if !reflect.DeepEqual(converted,arr){changed=append(changed,key)};continue }
   if _,ok:=want.(map[string]interface{});ok { var actual interface{};if len(query)!=1||json.Unmarshal([]byte(query[0]),&actual)!=nil||!reflect.DeepEqual(actual,want){changed=append(changed,key)};continue }
   if len(query)!=1||query[0]!=fmt.Sprint(want){changed=append(changed,key)}
  }
  row["missing"]=missing;row["changed"]=changed;delete(row,"expected");delete(row,"path");delete(row,"verb")
  rows=append(rows,row)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(rows);err!=nil {panic(err)}
}
'''
with tempfile.TemporaryDirectory(prefix='oathnet-go-parity-') as directory:
    path=pathlib.Path(directory)/'main.go';path.write_text(GO_HEADER+'\n'.join(cases)+GO_FOOTER)
    result=subprocess.run(['go','run',str(path)],cwd=ROOT,capture_output=True,text=True)
    if result.returncode:
        pathlib.Path('/tmp/oathnet-go-parity-failed.go').write_text(path.read_text())
        print(result.stderr,file=__import__('sys').stderr)
        print(json.dumps({'generation_failures':rows},indent=2))
        raise SystemExit(result.returncode)
    rows.extend(json.loads(result.stdout))
if args.output:args.output.write_text(json.dumps(rows,indent=2)+'\n')
failures=[r for r in rows if r.get('error') or r.get('missing') or r.get('changed') or not r.get('path_ok') or not r.get('verb_ok') or not r.get('auth_ok')]
print(json.dumps({'operations':len(rows),'parameters':sum(r.get('parameters',0) for r in rows),'failed':failures},indent=2))
raise SystemExit(bool(failures))
