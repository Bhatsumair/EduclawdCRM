const C="educlawd-v122",F=["./","index.html","manifest.webmanifest","icons/icon-192.png","icons/icon-512.png","icons/logo-96.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{if(e.request.method!=="GET"||new URL(e.request.url).origin!==location.origin)return;
e.respondWith(fetch(e.request).then(r=>{const c=r.clone();caches.open(C).then(x=>x.put(e.request,c));return r}).catch(()=>caches.match(e.request).then(m=>m||caches.match("index.html"))))});
/* task reminders sent by the server */
self.addEventListener("push",e=>{let d={};try{d=e.data?e.data.json():{}}catch(x){d={title:"Educlawd CRM",body:e.data?e.data.text():""}}
e.waitUntil(self.registration.showNotification(d.title||"Educlawd CRM",{body:d.body||"",tag:d.tag,renotify:true,icon:"icons/icon-192.png",badge:"icons/icon-192.png",data:{url:d.url||"./"},vibrate:[120,60,120]}))});
self.addEventListener("notificationclick",e=>{e.notification.close();const url=new URL((e.notification.data&&e.notification.data.url)||"./",self.location.origin).href;
e.waitUntil(self.clients.matchAll({type:"window",includeUncontrolled:true}).then(cs=>{for(const c of cs){if(c.url.startsWith(self.location.origin)&&"focus"in c){c.postMessage({go:"tasks"});return c.focus()}}return self.clients.openWindow(url)}))});
