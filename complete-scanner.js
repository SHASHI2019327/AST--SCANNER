"use strict";
// Self-contained static cryptographic inventory scanner. No npm dependencies required.
const fs = require('fs'), path = require('path'), crypto = require('crypto'), cp = require('child_process');
const { analyse, rank, LEVELS } = require('./risk-classifier');
const args = process.argv.slice(2); let target = args.find(x => !x.startsWith('--'));
const opt = { failOn: 'high', failQuantum: false, failOnUnknown: false, includeComments: false };
for (let i=0;i<args.length;i++) { if(args[i]==='--fail-on') opt.failOn=args[++i]; else if(args[i].startsWith('--fail-on=')) opt.failOn=args[i].split('=')[1]; else if(args[i]==='--fail-quantum') opt.failQuantum=true; else if(args[i]==='--fail-on-unknown') opt.failOnUnknown=true; else if(args[i]==='--include-comments') opt.includeComments=true; else if(args[i]==='-h'||args[i]==='--help'){ console.log('Usage: node complete-scanner.js <project-dir> [--fail-on none|critical|high|medium|low|unknown] [--fail-quantum] [--fail-on-unknown] [--include-comments]\n  Commented-out crypto is ignored by default; --include-comments lists it separately as category "comment" (low risk).\nExit: 0 pass, 1 policy violation, 2 scanner/setup error'); process.exit(0); } }
if (!target) { console.error('Target directory required.'); process.exit(2); }
if (!['none', ...LEVELS.filter(x => x !== 'safe')].includes(opt.failOn)) { console.error('Invalid --fail-on level. Use none, unknown, low, medium, high, or critical.'); process.exit(2); }
target=path.resolve(target); if(!fs.existsSync(target)||!fs.statSync(target).isDirectory()){console.error('Target directory not found: '+target);process.exit(2);}
const skip = new Set(['.git','node_modules','vendor','target','build','dist','.venv','venv','__pycache__','.next','coverage']);
// Risk level assigned to crypto that only appears inside comments (not executed). Change to 'unknown' or null-equivalent logic if you want the real risk shown.
const COMMENT_RISK = 'low';
const findings=[]; let filesScanned=0, parseErrors=[];
function push({algorithm, category='code', file, line=1, language='unknown', keySize=null, mode=null, api='', type='', operation='', reason='', riskOverride=null, quantumOverride=null, recommendation=''}) {
 const a=analyse({algorithm,language,keySize,mode,api,type,operation});
 let risk=riskOverride||a.risk, quantum=quantumOverride||a.quantum;
 findings.push({algorithm,category,risk,quantum,keySize:a.keySize||keySize||null,mode:a.mode||mode||null,languages:[language],reasons:[...(a.reasons||[]),...(reason?[reason]:[])],recommendation:[a.recommendation,recommendation].filter(Boolean).join(' '),occurrences:[{file,line,language,api:api||undefined}]});
}
function* walk(dir){let entries;try{entries=fs.readdirSync(dir,{withFileTypes:true})}catch(e){parseErrors.push(`${dir}: ${e.message}`);return;}for(const e of entries){if(e.isSymbolicLink()||skip.has(e.name)||e.name.startsWith('.git'))continue;const p=path.join(dir,e.name);if(e.isDirectory())yield*walk(p);else{try{if(fs.statSync(p).size<=3*1024*1024)yield p;}catch{}}}}
function rel(p){return path.relative(target,p).replace(/\\/g,'/');}
function addLine(algorithm,file,line,language,extra={}){push({algorithm,file:rel(file),line,language,...extra});}
const rules=[
 [/\bcreateHash\s*\(\s*['"]md5['"]|\bMD5(?:_Init|_Update|_Final)?\b|EVP_md5\s*\(/i,'MD5',{type:'hash'}],
 [/\bcreateHash\s*\(\s*['"]sha1['"]|\bSHA1?(?:_Init|_Update|_Final)?\b|EVP_sha1\s*\(/i,'SHA-1',{type:'hash'}],
 [/\b(?:DES_ecb|DES_cbc|DES_set_key|DES\.new)|EVP_des_[A-Za-z0-9_]+/i,'DES',{}], [/\bDES\b/,'DES',{}], [/\bAES\/(GCM|CBC|ECB|CTR|CCM|CFB|OFB|XTS)\b/i,'AES',m=>({mode:m[1].toUpperCase()})], [/\b(?:3DES|TripleDES|DESede|DESEDE|EVP_des_ede)\b/i,'3DES',{}], [/\b(?:RC4|ARCFOUR|EVP_rc4)\b/i,'RC4',{}],
 [/\b(?:AES|aes)[-_ ]?(128|192|256)[-_ ]?(GCM|CBC|ECB|CTR|CCM|CFB|OFB|XTS)\b|EVP_aes_(128|192|256)_(gcm|cbc|ecb|ctr|ccm|cfb|ofb|xts)/i,'AES',m=>({keySize:+(m[1]||m[3]),mode:(m[2]||m[4]||'').toUpperCase()})],
 [/\b(?:AES|aes)[-_ ]?(128|192|256)\b/i,'AES',m=>({keySize:+m[1]})], [/\bRSA(?:[-_ ]?(1024|2048|3072|4096))?\b/i,'RSA',m=>({keySize:m[1]?+m[1]:null})],
 [/\bECDSA[-_ ]?(?:P-?|SECP|prime)?(256|384|521)\b/i,'ECDSA',m=>({keySize:+m[1]})], [/\b(?:ECDSA|ECDH|X25519|X448|Ed25519|Ed448)\b/i,'ECDSA',{}], [/\b(?:DH|Diffie.Hellman)[-_ ]?(2048|3072|4096)?\b/i,'DH',m=>({keySize:m[1]?+m[1]:null})],
 [/\b(?:ML-KEM|Kyber|ML-DSA|Dilithium|SLH-DSA|SPHINCS\+?)\b/i,'ML-KEM',{}], [/\b(?:AES\.NewCipher|aes\.NewCipher)\s*\(/i,'AES',{}], [/\bAES\.new\s*\(/,'AES',{}]
];
const confExt=new Set(['.conf','.cnf','.cfg','.ini','.properties','.yml','.yaml','.toml']);
const depLibs={md5:['critical','MD5 package implements a broken hash','Replace with SHA-256/SHA-3.'],'sha1':['high','SHA-1 package is deprecated for collision-sensitive use','Replace with SHA-256/SHA-3.'],'pycrypto':['high','PyCrypto is unmaintained','Use maintained cryptography or pycryptodome.'],'crypto-js':['medium','Review maintenance and algorithm usage in crypto-js','Prefer platform crypto APIs and modern algorithms.'],'bcrypt':['safe','Password hashing library; confirm parameters are appropriate','Use a suitable work factor.'],'cryptography':['safe','Maintained cryptographic library; usage still requires review','Use modern algorithms and safe defaults.'],'pycryptodome':['safe','Library detected; review algorithms used','Prefer modern algorithms.'],'node-forge':['medium','Review dependency maintenance and cryptographic configuration','Keep patched and use modern algorithms.'],'jsonwebtoken':['medium','JWT library detected; verify allowed algorithms and reject none/weak algorithms','Pin allowed algorithms and validate issuer/audience.'],'jasypt':['medium','Jasypt may use weak legacy defaults unless configured','Configure modern authenticated encryption and strong password derivation.'],'commons-codec':['low','General-purpose codec dependency; inspect actual cryptographic use','Prefer modern digest algorithms.'],'bcprov':['safe','Bouncy Castle dependency detected; inspect configured algorithms','Keep updated.']};
function dep(name,file,line,lang,version=''){const n=name.toLowerCase();let entry=depLibs[n]||Object.entries(depLibs).find(([k])=>n.includes(k))?.[1]; if(!entry && !/(crypto|crypt|ssl|tls|jose|jwt|bcrypt|argon|scrypt|hash|cipher|openssl|keypair|pkcs|ssh|cert)/i.test(name))return; if(!entry)entry=['unknown','Cryptography-related dependency inventoried; actual algorithm usage and advisories are not determined from the manifest alone.','Inspect the resolved dependency tree, pin a supported version, and run the ecosystem package audit.'];push({algorithm:name+(version?'@'+version:''),category:'dependency',riskOverride:entry[0],quantumOverride:entry[0]==='safe'?'unknown':undefined,file:rel(file),line,language:lang,reason:entry[1],recommendation:entry[2]});}
for(const file of walk(target)){const ext=path.extname(file).toLowerCase(), name=path.basename(file).toLowerCase(), r=rel(file);let text;try{text=fs.readFileSync(file,'utf8');}catch(e){parseErrors.push(`${r}: ${e.message}`);continue;}filesScanned++;
 // Source-code inventory across JS/TS, Python, Java, Go, C/C++, Rust, C#, PHP, Ruby, Kotlin, Swift
 const langMap={'.js':'JavaScript','.jsx':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.py':'Python','.java':'Java','.go':'Go','.c':'C/C++','.h':'C/C++','.cc':'C/C++','.cpp':'C/C++','.hpp':'C/C++','.rs':'Rust','.cs':'C#','.php':'PHP','.rb':'Ruby','.kt':'Kotlin','.kts':'Kotlin','.swift':'Swift'};
if (langMap[ext]) {
    const language = langMap[ext];

    // Split the source into executable code and comments.
    // - Comments are blanked out of `code`, so prose cannot be mistaken for live code.
    // - String literals are KEPT in `code`, so createHash('md5'), Cipher.getInstance("DES/ECB/...")
    //   and similar calls are detected (they were previously blanked and therefore missed).
    // - The comment text is scanned separately and reported as category "comment",
    //   so commented-out crypto is visible in the dashboard too.
    function splitCodeAndComments(input, lang) {
        const hash = lang === 'Python' || lang === 'Ruby' || lang === 'PHP';
        const slash = lang !== 'Python' && lang !== 'Ruby';
        const code = input.split('');
        const com = code.map(c => (c === '\n' || c === '\r') ? c : ' ');
        const mv = i => { if (i < code.length && code[i] !== '\n' && code[i] !== '\r') { com[i] = code[i]; code[i] = ' '; } };
        let state = 'code', quote = '', esc = false;
        for (let i = 0; i < input.length; i++) {
            const c = input[i], n = input[i + 1] || '';
            if (state === 'line') { if (c === '\n') state = 'code'; else mv(i); continue; }
            if (state === 'block') { mv(i); if (c === '*' && n === '/') { mv(i + 1); i++; state = 'code'; } continue; }
            if (state === 'tstr') { if (c === quote && n === quote && input[i + 2] === quote) { i += 2; state = 'code'; } else if (c !== '\n' && c !== '\r') code[i] = ' '; continue; }
            if (state === 'str') {
                if (esc) { esc = false; continue; }
                if (c === '\\') { esc = true; continue; }
                if (c === quote) { state = 'code'; continue; }
                if (c === '\n' && quote !== '`') state = 'code';
                continue;
            }
            if (slash && c === '/' && n === '/') { mv(i); mv(i + 1); i++; state = 'line'; continue; }
            if (slash && c === '/' && n === '*') { mv(i); mv(i + 1); i++; state = 'block'; continue; }
            if (hash && c === '#') { mv(i); state = 'line'; continue; }
            if (c === '"' || c === "'" || c === '`') {
                quote = c;
                if (lang === 'Python' && input[i + 1] === c && input[i + 2] === c) { state = 'tstr'; i += 2; }
                else state = 'str';
            }
        }
        return { code: code.join(''), comments: com.join('') };
    }

    function scanText(src, category) {
        src.split(/\r?\n/).forEach((ln, i) => {
            if (!ln.trim()) return;
            for (const [re, algo, fn] of rules) {
                const m = ln.match(re);
                if (!m) continue;
                const extra = typeof fn === 'function' ? fn(m) : (fn || {});
                let mode = extra.mode;
                if (!mode) {
                    const mm = ln.match(/(?:\b|_)(GCM|CBC|ECB|CTR|CCM|CFB|OFB|XTS)\b/i);
                    if (mm && /AES|Cipher|cipher|encrypt|Encrypt/i.test(ln)) mode = mm[1].toUpperCase();
                }
                if (category === 'comment') {
                    const live = analyse({ algorithm: algo, language, keySize: extra.keySize || null, mode, api: '', type: extra.type || '', operation: '' });
                    addLine(algo, file, i + 1, language, {
                        ...extra, mode, api: 'comment', category: 'comment',
                        riskOverride: COMMENT_RISK,
                        reason: `Mentioned in a source comment, not executable code. If this were active code it would rate "${live.risk}".`,
                        recommendation: 'Confirm the comment is stale or documentation only; remove it or keep the algorithm out of the codebase.'
                    });
                } else {
                    addLine(algo, file, i + 1, language, { ...extra, mode, api: 'source-pattern' });
                }
            }
        });
    }

    const { code, comments } = splitCodeAndComments(text, language);
    // Python: the AST scanner (below) gives precise call-level findings; this regex pass adds anything it does not model
    // (DES/ARC4/AES.new, imports, ...). Docstrings are blanked and duplicates are merged later.
    scanText(code, 'code');
    if (opt.includeComments) scanText(comments, 'comment');
}
 // Dependency manifests, including common lock/requirements formats
 if(name==='package.json'){try{const j=JSON.parse(text);for(const section of ['dependencies','devDependencies','optionalDependencies','peerDependencies'])for(const [n,v] of Object.entries(j[section]||{}))dep(n,file,Math.max(1,text.slice(0,text.indexOf('"'+n+'"')).split('\n').length),'JavaScript',String(v));}catch(e){parseErrors.push(`${r}: invalid package.json: ${e.message}`)}}
 if(/^requirements.*\.txt$/.test(name)||name==='constraints.txt'){text.split(/\r?\n/).forEach((ln,i)=>{const m=ln.match(/^\s*([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(?:[<>=!~].*)?$/);if(m)dep(m[1],file,i+1,'Python',ln.match(/[<>=!~].*/)?.[0]||'');});}
 if(name==='pom.xml'||name==='build.gradle'||name==='build.gradle.kts'){const re=name==='pom.xml'?/<artifactId>\s*([^<]+)\s*<\/artifactId>/g:/(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['"]([^'"]+)['"]/g;for(const m of text.matchAll(re)){const id=m[1].split(':').pop();dep(id,file,text.slice(0,m.index).split('\n').length,'Java');}}
 if(name==='go.mod'){for(const m of text.matchAll(/^\s*([^\s()]+)\s+v?([^\s]+)\s*$/gm))dep(m[1],file,text.slice(0,m.index).split('\n').length,'Go',m[2]);}
 if(name==='cargo.toml'){for(const m of text.matchAll(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']([^"']+)["']/gm))dep(m[1],file,text.slice(0,m.index).split('\n').length,'Rust',m[2]);}
 // TLS / SSH / nginx / application configuration
 if(confExt.has(ext)||/^(sshd?_config|nginx\.conf|dockerfile|\.env)$/.test(name)||/^(Dockerfile|Containerfile)$/.test(path.basename(file))){text.split(/\r?\n/).forEach((ln,i)=>{if(/^\s*(#|;|\/\/)/.test(ln))return;const at=(a,r,why,fix,q='unknown')=>push({algorithm:a,category:'configuration',riskOverride:r,quantumOverride:q,file:rel(file),line:i+1,language:'Configuration',reason:why,recommendation:fix});
 if(/\b(?:SSLv2|SSLv3)\b/i.test(ln))at('SSLv2/SSLv3','critical','Obsolete SSL protocol enabled or permitted','Disable SSL; require TLS 1.2 or TLS 1.3.');
 if(/\b(?:TLSv?1(?:\.0)?|TLSv?1\.1)\b/i.test(ln)&&/(protocol|tls|ssl|minimum|minprotocol|maximum|maxprotocol|ssl_protocols|TLS)/i.test(ln))at('TLS 1.0/1.1','high','Deprecated TLS protocol enabled or permitted','Require TLS 1.2+; prefer TLS 1.3.');
 if(/\bProtocol\s+1\b/i.test(ln))at('SSH protocol 1','critical','SSH protocol 1 is obsolete and insecure','Set Protocol 2 or remove Protocol directive on modern OpenSSH.');
 const weak=ln.match(/\b(3DES|DES|RC4|ARCFOUR|MD5|EXPORT|NULL|aNULL|eNULL|LOW)\b/i);if(weak&&/(cipher|crypto|mac|kex|hostkey|ssh|ssl|tls)/i.test(ln))at('Weak config: '+weak[1].toUpperCase(),'high',`Weak algorithm ${weak[1]} is allowed by configuration`,'Remove weak algorithms; prefer AEAD ciphers and SHA-2 MACs.');
 if(/\b(hmac-sha1|ssh-rsa)\b/i.test(ln)&&/(mac|hostkey|pubkey|algorithm|accepted|ssh)/i.test(ln))at(ln.match(/hmac-sha1|ssh-rsa/i)[0],'medium','Legacy SSH MAC or signature algorithm allowed','Prefer modern SHA-2 or supported post-quantum/hybrid options.');
 if(/ssl_protocols\s+[^;]*TLSv1(?:\s|;|$)/i.test(ln))at('TLS 1.0','high','nginx permits legacy TLS','Set ssl_protocols TLSv1.2 TLSv1.3;');
 });}
 // PEM certificates and private keys
 if(['.pem','.crt','.cer','.key'].includes(ext)){for(const m of text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g)){const label=m[1],line=text.slice(0,m.index).split('\n').length;try{if(label.includes('PRIVATE KEY')){let key;try{key=crypto.createPrivateKey(m[0]);}catch(e){push({algorithm:'Unparsed private key ('+label+')',category:'key-material',riskOverride:'critical',quantumOverride:'unknown',file:r,line,language:'Key material',reason:'Private key is present; encrypted/unsupported format prevented metadata extraction.',recommendation:'Remove from repository, rotate if exposed, and inspect with a trusted key tool.'});continue;}const typ=key.asymmetricKeyType,det=key.asymmetricKeyDetails||{};const alg=typ==='rsa'?'RSA':typ==='ec'?'ECDSA':typ==='ed25519'?'Ed25519':typ==='ed448'?'Ed448':String(typ||'Unknown');const size=det.modulusLength||(det.namedCurve&&Number((det.namedCurve.match(/(256|384|521)/)||[])[1]))||null;push({algorithm:alg,category:'key-material',riskOverride:'critical',file:r,line,language:'Key material',keySize:size,reason:'Private key committed to repository; key exposure is critical independently of algorithm strength.',recommendation:'Remove from repository, rotate/revoke the key, and use a secret manager.'});}
 else if(label==='CERTIFICATE'){const cert=new crypto.X509Certificate(m[0]),key=cert.publicKey,typ=key.asymmetricKeyType,det=key.asymmetricKeyDetails||{};const alg=typ==='rsa'?'RSA':typ==='ec'?'ECDSA':String(typ||'Unknown');const size=det.modulusLength||(det.namedCurve&&Number((det.namedCurve.match(/(256|384|521)/)||[])[1]))||null;push({algorithm:alg,category:'certificate',file:r,line,language:'Certificate',keySize:size,reason:`Certificate subject ${cert.subject.replace(/\n/g,', ')}; expires ${cert.validTo}.`,recommendation:new Date(cert.validTo)<new Date()?'Renew expired certificate.':'Review trust, expiry, and migration plan.'});if(new Date(cert.validTo)<new Date())findings[findings.length-1].risk=rank(findings[findings.length-1].risk)<rank('medium')?'medium':findings[findings.length-1].risk;}
 }catch(e){parseErrors.push(`${r}: certificate/key parse failed: ${e.message}`)}}}
 // Binary keystores: report exposure; use keytool when installed for metadata (never extract secrets)
 if(['.jks','.keystore','.p12','.pfx'].includes(ext)){let reason='Keystore file committed; contents were not parsed automatically.';let rec='Remove from repository and store securely. Use keytool for JKS/JCEKS or a controlled PKCS#12 inspection workflow.';const probe=cp.spawnSync('keytool',['-list','-keystore',file,'-storepass','changeit'],{encoding:'utf8',timeout:3000,windowsHide:true});if(!probe.error&&probe.status===0){reason='Keystore recognized by keytool; aliases/certificate metadata can be inspected with keytool.';rec='Remove from repository; rotate exposed private keys and use a secret manager.';}push({algorithm:'Keystore file',category:'key-material',riskOverride:'high',quantumOverride:'unknown',file:r,line:1,language:'Key material',reason,recommendation:rec});}
}
// Run the Python AST scanner and merge its findings.
// Python source is excluded from the generic regex scan above so
// comments and docstrings cannot create Python code findings.
const pythonScanner = path.join(__dirname, 'python-scanner.py');
const pythonOutput = path.join(__dirname, 'python-findings.json');

const pyCmd = cp.spawnSync('python', ['--version'], { windowsHide: true }).error ? 'python3' : 'python';
const pythonRun = cp.spawnSync(
    pyCmd,
    [pythonScanner, target, '--output', pythonOutput],
    {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 120000
    }
);

if (pythonRun.error) {
    parseErrors.push(
        'Python AST scanner could not start: ' + pythonRun.error.message
    );
} else if (pythonRun.status !== 0) {
    parseErrors.push(
        'Python AST scanner failed: ' +
        (pythonRun.stderr || pythonRun.stdout || 'Unknown error')
    );
} else {
    try {
        const pythonData = JSON.parse(
            fs.readFileSync(pythonOutput, 'utf8')
        );

        for (const item of (pythonData.items || [])) {
            findings.push(item);
        }

        for (const error of (pythonData.errors || [])) {
            parseErrors.push(String(error));
        }

        console.log(
            'Python AST findings merged: ' +
            (pythonData.items || []).length
        );
    } catch (error) {
        parseErrors.push(
            'Could not read Python findings: ' + error.message
        );
    }
}
// de-duplicate: one finding per algorithm/category/file/line; keep the most detailed (key size / mode) and merge reasons
const byKey=new Map();for(const f of findings){const o=f.occurrences[0]||{};const k=[f.algorithm,f.category,o.file,o.line].join('|').toLowerCase();const cur=byKey.get(k);if(!cur){byKey.set(k,f);continue;}const sc=x=>(x.keySize?1:0)+(x.mode?1:0);const [best,other]=sc(f)>sc(cur)?[f,cur]:[cur,f];if(!best.keySize&&other.keySize)best.keySize=other.keySize;if(!best.mode&&other.mode)best.mode=other.mode;byKey.set(k,best);}
const unique=[...byKey.values()];
unique.sort((a,b)=>rank(b.risk)-rank(a.risk)||a.algorithm.localeCompare(b.algorithm));
const summary={filesScanned,total:unique.length,byRisk:{},quantumVulnerable:0,quantumWeakened:0,parseErrors:parseErrors.length};for(const l of LEVELS)summary.byRisk[l]=unique.filter(f=>f.risk===l).length;summary.quantumVulnerable=unique.filter(f=>f.quantum==='vulnerable').length;summary.quantumWeakened=unique.filter(f=>f.quantum==='weakened').length;
const outDir=__dirname;fs.writeFileSync(path.join(outDir,'risk-report.json'),JSON.stringify({generatedAt:new Date().toISOString(),summary,items:unique},null,2));fs.writeFileSync(path.join(outDir,'extra-report.json'),JSON.stringify({generatedAt:new Date().toISOString(),summary,items:unique},null,2));
// CycloneDX 1.6 CBOM-style inventory with cryptographic components and risk properties.
const components=unique.map((f,i)=>{const p=f.occurrences[0]||{};const assetType=f.category==='certificate'?'certificate':f.category==='key-material'?'related-crypto-material':f.category==='configuration'?'protocol':f.category==='dependency'?'algorithm':'algorithm';const props=[['cbom:risk-level',f.risk],['cbom:quantum-status',f.quantum],['cbom:source-file',p.file||''],['cbom:source-line',p.line||''],['cbom:category',f.category],['cbom:recommendation',f.recommendation||'']].filter(x=>String(x[1])!=='');if(f.keySize)props.push(['cbom:key-size-bits',f.keySize]);if(f.mode)props.push(['cbom:mode',f.mode]);return {type:'cryptographic-asset',name:f.algorithm,version:'unknown',description:[...(f.reasons||[])].join(' '),cryptoProperties:{assetType,algorithmProperties:assetType==='algorithm'?{primitive:(/MD5|SHA|BLAKE|SHAKE/i.test(f.algorithm)?'hash':/AES|DES|RC4|CHACHA/i.test(f.algorithm)?'block-cipher':/RSA|ECDSA|ED25519|ED448|ML-DSA|SLH-DSA/i.test(f.algorithm)?'signature':/KEM|ECDH|DH|X25519/i.test(f.algorithm)?'key-agree':'other'),parameterSetIdentifier:f.keySize?String(f.keySize):undefined,mode:f.mode?f.mode.toLowerCase():undefined}:undefined},properties:props.map(([name,value])=>({name,value:String(value)}))};});
const bom={bomFormat:'CycloneDX',specVersion:'1.6',version:1,metadata:{timestamp:new Date().toISOString(),tools:{components:[{type:'application',name:'AST-SCANNER',version:'2.0.0'}]},properties:[{name:'cbom:scanner-target',value:target},{name:'cbom:scan-files',value:String(filesScanned)}]},components};fs.writeFileSync(path.join(outDir,'cbom.json'),JSON.stringify(bom,null,2));
// Dashboard from existing template, when available.
try{const tpl=fs.readFileSync(path.join(outDir,'dashboard-template.html'),'utf8');const data=JSON.stringify({generatedAt:new Date().toISOString(),items:unique}).replace(/</g,'\\u003c');fs.writeFileSync(path.join(outDir,'cbom-dashboard.html'),tpl.replace('__DATA__',()=>data));}catch(e){console.warn('Dashboard not rebuilt: '+e.message)}
console.log('\nAST-SCANNER comprehensive static scan');console.log('Target: '+target);console.log(`Files scanned: ${filesScanned}; findings: ${unique.length}; quantum-vulnerable: ${summary.quantumVulnerable}`);console.log('Risk counts: '+JSON.stringify(summary.byRisk));if(parseErrors.length)console.warn(`Non-fatal parse/read issues: ${parseErrors.length} (see scanner-errors.json)`);fs.writeFileSync(path.join(outDir,'scanner-errors.json'),JSON.stringify(parseErrors,null,2));
// Validate the generated BOM before declaring the scan successful.
const validation = cp.spawnSync(process.execPath, [path.join(__dirname, 'validate-cbom.js')], { encoding: 'utf8', windowsHide: true });
if (validation.stdout) process.stdout.write(validation.stdout);
if (validation.stderr) process.stderr.write(validation.stderr);
if (validation.error || validation.status !== 0) { console.error('CBOM schema validation failed; refusing to report a successful scan.'); process.exit(2); }
const threshold=opt.failOn==='none'?Infinity:rank(opt.failOn);const violations=unique.filter(f=>(opt.failOn!=='none'&&rank(f.risk)>=threshold)||(opt.failQuantum&&f.quantum==='vulnerable')||(opt.failOnUnknown&&f.risk==='unknown'));if(violations.length){console.error(`CI GATE: FAIL (${violations.length} finding(s) at threshold ${opt.failOn}${opt.failQuantum?', quantum-vulnerable':''})`);process.exit(1);}console.log('CI GATE: PASS');process.exit(0);