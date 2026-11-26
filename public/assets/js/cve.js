import './components.js';
const q = new URLSearchParams(location.search);
const get = (key, fallback='Not provided') => (q.get(key) || fallback).slice(0, 12000);
const parse = (key, fallback) => { try { return JSON.parse(get(key, JSON.stringify(fallback))); } catch { return fallback; } };
const id = get('id', 'Dependency vulnerability');
document.title = id + ' analysis - FlawRadar';
document.querySelector('#cve-title').textContent = id;
const meta = document.querySelector('#cve-meta');
for (const value of [get('package'), 'Version ' + get('version'), get('ecosystem'), 'Severity ' + get('severity')]) { const span=document.createElement('span'); span.textContent=value; meta.append(span); }
document.querySelector('#cve-summary').textContent=get('summary','The installed dependency matched an advisory record. Confirm the affected conditions in the primary reference.');
document.querySelector('#cve-location').textContent='Detected in '+get('file')+' at line '+get('line','1')+'.';
document.querySelector('#cve-dates').textContent='Published: '+get('published','unknown')+' · Last modified: '+get('modified','unknown')+' · OSV: '+get('osv','not supplied');
document.querySelector('#cve-details').textContent=get('details','No detailed advisory text was returned. Use the primary advisory reference to confirm the technical conditions.');
document.querySelector('#cve-package').textContent=`Matched dependency: ${get('ecosystem')} / ${get('package')} @ ${get('version')}`;
document.querySelector('#cve-fix').textContent=get('fix','Upgrade to a vendor-confirmed fixed version. If no fixed release exists, apply vendor mitigation and reassess exposure.');
const cvss=get('cvss',''); const cvssBase=get('cvssBase',''); const epss=parse('epss',null); const kev=parse('kev',null);
const signalRows=[['CVSS base',cvssBase ? `${cvssBase} / 10` : 'Not supplied'],['EPSS',epss?.score!=null ? `${(epss.score*100).toFixed(2)}% (30-day estimate)` : 'Unavailable'],['EPSS percentile',epss?.percentile!=null ? `${(epss.percentile*100).toFixed(1)}th percentile` : 'Unavailable'],['CISA KEV',kev ? 'Listed as known exploited' : 'No KEV match returned']];
const signals=document.querySelector('#cve-signals'); for(const [label,value] of signalRows){const box=document.createElement('div');box.className='cve-signal';const b=document.createElement('b');b.textContent=label;const v=document.createElement('span');v.textContent=value;box.append(b,v);signals.append(box);}
if(cvss) {const p=document.createElement('p');p.textContent='CVSS vector: '+cvss;signals.after(p);}
if(kev){const p=document.createElement('p');p.textContent=`CISA KEV added: ${kev.dateAdded||'date unavailable'} · Due: ${kev.dueDate||'not listed'} · ${kev.requiredAction||'Follow the vendor remediation guidance.'}`;signals.after(p);}
const metrics=cvss?Object.fromEntries(cvss.split('/').slice(1).map(part=>part.split(':'))):{};
const labels={AV:{N:'Network reachable',A:'Adjacent network',L:'Local access',P:'Physical access'},AC:{L:'Low complexity',H:'High complexity'},PR:{N:'No privileges required',L:'Low privileges required',H:'High privileges required'},UI:{N:'No user interaction required',R:'User interaction required'},S:{U:'Same security scope',C:'Changed security scope'},C:{H:'High confidentiality impact',L:'Low confidentiality impact',N:'No confidentiality impact'},I:{H:'High integrity impact',L:'Low integrity impact',N:'No integrity impact'},A:{H:'High availability impact',L:'Low availability impact',N:'No availability impact'}};
const vectorText=Object.entries(metrics).map(([key,value])=>labels[key]?.[value]).filter(Boolean);
document.querySelector('#cve-mechanism').textContent=vectorText.length?`CVSS vector interpretation: ${vectorText.join('; ')}. These are scoring characteristics from the advisory, not proof that the affected code path is reachable in this project.`:get('details','The advisory record does not include enough detail to identify a specific code-level mechanism. Consult the vendor advisory before drawing conclusions.');
const impactNames=[['Confidentiality',metrics.C],['Integrity',metrics.I],['Availability',metrics.A]].map(([name,value])=>`${name}: ${{H:'High',L:'Low',N:'None'}[value]||'Not stated'}`).join(' · ');
document.querySelector('#cve-impact').textContent=metrics.C||metrics.I||metrics.A?impactNames:get('summary','Impact must be determined from the vendor advisory and the affected application context.');
const ranges=document.querySelector('#cve-ranges'); const rangeData=parse('ranges',[]); ranges.textContent=rangeData.length?JSON.stringify(rangeData,null,2):'No version events supplied.';
const packages=parse('affectedPackages',[]); const packageHolder=document.querySelector('#cve-affected-packages');
if(packages.length){const ul=document.createElement('ul');for(const item of packages.slice(0,40)){const li=document.createElement('li');li.textContent=`${item.ecosystem}: ${item.name}`;ul.append(li);}packageHolder.append(ul);}else packageHolder.textContent='No affected-package list was included in the returned advisory record.';
const aliases=parse('aliases',[]); document.querySelector('#cve-aliases').textContent=aliases.length?'Related identifiers: '+aliases.join(', '):'No alternate identifiers supplied.';
const refs=document.querySelector('#cve-references'); const list=parse('refs',[]);
if(!list.length) refs.textContent='No external references were provided.';
else for(const item of list.slice(0,12)){if(!item||typeof item.url!=='string'||!/^https:\/\//i.test(item.url))continue;const li=document.createElement('li');const a=document.createElement('a');a.href=item.url;a.textContent=item.type||'Advisory reference';a.rel='noopener noreferrer';a.target='_blank';li.append(a);refs.append(li);}
