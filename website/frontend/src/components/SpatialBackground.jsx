"use client";
import React from 'react';

export default function SpatialBackground() {
  return (
    <div className="spatial-stage">
      {/* Deep Layer (Max distance, heavily blurred) */}
      <div className="spatial-card depth-deep pos-1">
        <div className="card-inner">
          <span className="icon">⬡</span>
          <div>SYS.SEC // OK</div>
        </div>
      </div>
      <div className="spatial-card depth-deep pos-2">
        <div className="card-inner">
          <span className="icon">⬡</span>
          <div>NODE 44.A</div>
        </div>
      </div>
      <div className="spatial-card depth-deep pos-7">
        <div className="card-inner">
          <div className="tech-header">ADVISORY // 01</div>
          <div className="tech-code">Check for valid .gov.in TLDs.</div>
        </div>
      </div>

      {/* Mid Layer (Intermediate distance, medium blur) */}
      <div className="spatial-card depth-mid pos-3">
        <div className="card-inner">
          <div className="tech-header">IP ROUTING LOG</div>
          <div className="tech-code">
            &gt; TRACE 192.168.x.x<br/>
            &gt; HOP 1: SECURE<br/>
            &gt; HOP 2: VERIFIED
          </div>
        </div>
      </div>
      <div className="spatial-card depth-mid pos-4">
        <div className="card-inner">
          <div className="tech-header">DATA HASH</div>
          <div className="tech-code">0x9F4B...A210</div>
        </div>
      </div>
      <div className="spatial-card depth-mid pos-8">
        <div className="card-inner">
          <div className="tech-header">GUIDELINE: PHISHING</div>
          <div className="tech-code">
            Govt agencies will NEVER ask<br/>for your OTP or ATM PIN via SMS.
          </div>
        </div>
      </div>
      <div className="spatial-card depth-mid pos-10">
        <div className="card-inner">
          <div className="tech-header">SSL VERIFICATION</div>
          <div className="tech-code">
            Always ensure the lock icon<br/>is present before submitting PII.
          </div>
        </div>
      </div>
      <div className="spatial-card depth-mid pos-11">
        <div className="card-inner">
          <div className="tech-header">DOMAIN HEURISTICS</div>
          <div className="tech-code">
            Scanning for homoglyphs<br/>
            (e.g., g0v.in vs gov.in)
          </div>
        </div>
      </div>

      {/* Foreground Layer (Closest, detailed, slight blur) */}
      <div className="spatial-card depth-front pos-5">
        <div className="card-inner">
          <div className="tech-header threat-text">THREAT GAUGE</div>
          <div className="gauge-bar"><div className="gauge-fill"></div></div>
          <div className="tech-code">LEVEL: ELEVATED</div>
        </div>
      </div>
      <div className="spatial-card depth-front pos-6">
        <div className="card-inner">
          <div className="tech-header">VERIFICATION METRICS</div>
          <div className="tech-code">
            SIG: MATCH<br/>
            SSL: VALID<br/>
            BIOMETRIC: PENDING...
          </div>
        </div>
      </div>
      <div className="spatial-card depth-front pos-9">
        <div className="card-inner">
          <div className="tech-header">REPORT CYBERCRIME</div>
          <div className="tech-code">
            Helpline: 1930<br/>
            Portal: cybercrime.gov.in
          </div>
        </div>
      </div>
    </div>
  );
}
