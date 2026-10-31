"use strict";
(() => {
  const body = document.body;
  const shell = document.getElementById("cinema-scroll");
  const frame = document.getElementById("cinema-frame");
  const landscape = document.getElementById("landscape");
  const canvas = document.getElementById("signal-field");
  const ctx = canvas.getContext("2d");
  const pointer = {x:0,y:0};
  let width=0,height=0,raf=0,lastFrame=0,elapsed=0,visible=true;
  const points=Array.from({length:48},(_,i)=>({x:((i*137.508)%100)/100,y:.32+((i*47.31)%60)/100,phase:i*.71}));
  const paused=()=>body.classList.contains("motion-paused")||matchMedia("(prefers-reduced-motion: reduce)").matches;
  const inLab=()=>location.hash==="#lab";
  function resize(){const box=frame.getBoundingClientRect();width=frame.clientWidth;height=frame.clientHeight;const ratio=Math.min(devicePixelRatio||1,2);canvas.width=width*ratio;canvas.height=height*ratio;ctx?.setTransform(ratio,0,0,ratio,0,0);updateScroll();draw();}
  function updateScroll(){
    body.classList.toggle("hero-scrolled", !inLab()&&scrollY>innerHeight*.65);
    if(inLab())return;
    const distance=Math.max(1,shell.offsetHeight-innerHeight);
    const progress=Math.min(1,Math.max(0,scrollY/distance));
    frame.style.transform=paused()?"none":`scale(${1-progress*.18})`;
    landscape.style.transform=paused()?"none":`scale(1.055) translate(${pointer.x*10}px,${pointer.y*7+progress*24}px)`;
  }
  function draw(){
    if(!ctx)return;
    ctx.clearRect(0,0,width,height);
    const positions=points.map(p=>({x:p.x*width+(paused()?0:Math.sin(elapsed*.2+p.phase)*10)+pointer.x*(9+p.phase%9),y:p.y*height+(paused()?0:Math.cos(elapsed*.16+p.phase)*8)+pointer.y*10}));
    positions.forEach((p,i)=>{
      for(let j=i+1;j<positions.length;j++){const q=positions[j];const distance=Math.hypot(p.x-q.x,p.y-q.y);if(distance<width*.115){ctx.strokeStyle=`rgba(231,214,176,${.16*(1-distance/(width*.115))})`;ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);ctx.stroke();}}
      ctx.fillStyle=`rgba(243,224,180,${.38+.18*Math.sin(elapsed+points[i].phase)})`;ctx.beginPath();ctx.arc(p.x,p.y,i%5===0?2:1,0,Math.PI*2);ctx.fill();
    });
  }
  function tick(time){raf=0;if(document.hidden||inLab()||!visible||paused())return;if(time-lastFrame>32){elapsed+=Math.min((time-lastFrame)/1000,.05);lastFrame=time;draw();}raf=requestAnimationFrame(tick);}
  function sync(){cancelAnimationFrame(raf);raf=0;updateScroll();draw();if(!paused()&&!inLab()&&visible&&!document.hidden){lastFrame=performance.now();raf=requestAnimationFrame(tick);}}
  frame.addEventListener("pointermove",event=>{if(paused()||event.pointerType==="touch")return;const box=frame.getBoundingClientRect();pointer.x=(event.clientX-box.left)/box.width-.5;pointer.y=(event.clientY-box.top)/box.height-.5;updateScroll();});
  frame.addEventListener("pointerleave",()=>{pointer.x=pointer.y=0;updateScroll();});
  window.addEventListener("resize",resize);
  let scrollQueued=false;
  window.addEventListener("scroll",()=>{if(!scrollQueued){scrollQueued=true;requestAnimationFrame(()=>{updateScroll();scrollQueued=false;});}},{passive:true});
  document.addEventListener("visibilitychange",sync);document.addEventListener("motionchange",sync);document.addEventListener("viewchange",()=>{resize();sync();});
  new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;sync();}).observe(frame);
  document.getElementById("scroll-invitation").addEventListener("click",()=>document.getElementById("prologue").scrollIntoView({behavior:paused()?"instant":"smooth"}));
  const reveals=document.querySelectorAll(".scroll-reveal");
  const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add("is-visible");observer.unobserve(entry.target);}}),{threshold:.12});
  reveals.forEach(el=>observer.observe(el));body.classList.add("js-experience");
  const explanations=["Browse the local zone's signed service index, then inspect the published SVCB records for each endpoint and supported capability.","The client checks DNS signatures, metadata and the address record. TLS then verifies the endpoint identity before a token is sent.","The service independently checks its access token. Accepted health requests can return a live snapshot; latency and traceroute return clearly labelled samples."];
  const names=["DISCOVER","VERIFY","CONNECT"];
  document.querySelectorAll(".journey-step").forEach(button=>button.addEventListener("click",()=>{const index=Number(button.dataset.step);document.querySelectorAll(".journey-step").forEach(b=>{b.classList.toggle("active",b===button);b.setAttribute("aria-pressed",String(b===button));});document.getElementById("map-glyph").textContent=`0${index+1}`;document.getElementById("map-label").textContent=names[index];document.getElementById("journey-explanation").textContent=explanations[index];document.getElementById("journey-map").style.setProperty("--map-turn",`${(index-1)*12}deg`);}));
  document.querySelectorAll(".magnetic").forEach(link=>{link.addEventListener("pointermove",event=>{if(paused()||event.pointerType==="touch")return;const b=link.getBoundingClientRect();link.style.transform=`translate(${(event.clientX-b.left-b.width/2)*.16}px,${(event.clientY-b.top-b.height/2)*.16}px)`;});link.addEventListener("pointerleave",()=>{link.style.transform="";});});
  document.querySelectorAll('a[href="#lab"],a[href="#welcome"]').forEach(link=>link.addEventListener("click",()=>{if(paused()||link.hash===location.hash)return;const wipe=document.querySelector(".scene-wipe");wipe.classList.remove("transitioning");void wipe.offsetWidth;wipe.classList.add("transitioning");}));
  resize();sync();
})();
