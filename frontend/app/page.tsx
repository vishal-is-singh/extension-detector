"use client";
import { useState, useCallback } from "react";

interface ScanResult {
  verdict: string;
  risk_score: number;
  confidence_benign: number;
  confidence_malicious: number;
  js_files: string[];
  dangerous_permissions: string[];
  suspicious_patterns: { pattern: string; count: number }[];
  warnings: string[];
  extension_name: string;
  error?: string;
}

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState("");

  const scanFile = async (file: File) => {
    setLoading(true);
    setError("");
    setResult(null);
    setFileName(file.name);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await fetch("http://localhost:8000/scan-zip", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.error) setError(data.error);
      else setResult(data);
    } catch {
      setError("Cannot connect to backend. Make sure backend.py is running.");
    }
    setLoading(false);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) scanFile(file);
  }, []);

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) scanFile(file);
  };

  const getRiskColor = (score: number) =>
    score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#22c55e";

  const getRiskLabel = (score: number) =>
    score >= 70 ? "High Risk" : score >= 40 ? "Medium Risk" : "Low Risk";

  return (
    <main style={{ minHeight: "100vh", background: "#0a0a0f", color: "white", padding: "2rem 1rem", fontFamily: "system-ui, sans-serif" }}>
      <div style={{ maxWidth: "680px", margin: "0 auto" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: "2.5rem" }}>
          <div style={{ fontSize: "2.5rem", marginBottom: "0.5rem" }}>🛡️</div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "700", margin: "0 0 0.5rem", color: "white" }}>
            Extension Detector
          </h1>
          <p style={{ color: "#6b7280", fontSize: "1rem", margin: 0 }}>
            AI-powered malicious browser extension identifier
          </p>
        </div>

        {/* Drop Zone */}
        <div
          onDrop={onDrop}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          style={{
            border: `2px dashed ${dragging ? "#3b82f6" : "#2d2d3a"}`,
            borderRadius: "16px",
            padding: "3rem 2rem",
            textAlign: "center",
            background: dragging ? "#0f1729" : "#111118",
            transition: "all 0.2s",
            cursor: "pointer",
            marginBottom: "1.5rem",
          }}
          onClick={() => document.getElementById("fileInput")?.click()}
        >
          <input
            id="fileInput"
            type="file"
            accept=".zip,.crx"
            style={{ display: "none" }}
            onChange={onFileInput}
          />
          {loading ? (
            <div>
              <div style={{ fontSize: "2rem", marginBottom: "1rem" }}>⏳</div>
              <p style={{ color: "#3b82f6", fontWeight: "600", margin: "0 0 0.25rem" }}>
                Scanning {fileName}...
              </p>
              <p style={{ color: "#6b7280", fontSize: "0.875rem", margin: 0 }}>
                AI model is analyzing the extension
              </p>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: "2.5rem", marginBottom: "1rem" }}>📦</div>
              <p style={{ color: "white", fontWeight: "600", fontSize: "1.1rem", margin: "0 0 0.5rem" }}>
                Drop your extension here
              </p>
              <p style={{ color: "#6b7280", fontSize: "0.875rem", margin: "0 0 1.5rem" }}>
                Supports .zip and .crx files
              </p>
              <div style={{
                display: "inline-block",
                background: "#1d4ed8",
                color: "white",
                padding: "0.6rem 1.5rem",
                borderRadius: "8px",
                fontSize: "0.875rem",
                fontWeight: "600",
              }}>
                Browse File
              </div>
            </div>
          )}
        </div>

        {/* How to get a .zip */}
        <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "12px", padding: "1rem 1.25rem", marginBottom: "1.5rem" }}>
          <p style={{ color: "#6b7280", fontSize: "0.8rem", margin: "0 0 0.5rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            How to get an extension file
          </p>
          <p style={{ color: "#9ca3af", fontSize: "0.875rem", margin: 0, lineHeight: "1.6" }}>
            1. Go to <span style={{ color: "#3b82f6" }}>chrome://extensions</span> → enable Developer Mode<br />
            2. Find any extension → click <strong style={{ color: "white" }}>Pack Extension</strong><br />
            3. Or download a <strong style={{ color: "white" }}>.crx / .zip</strong> from any extension source
          </p>
        </div>

        {/* Error */}
        {error && (
          <div style={{ background: "#1f0a0a", border: "1px solid #7f1d1d", borderRadius: "12px", padding: "1rem 1.25rem", marginBottom: "1.5rem", color: "#fca5a5", fontSize: "0.875rem" }}>
            ⚠️ {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>

            {/* Verdict */}
            <div style={{
              background: result.verdict === "MALICIOUS" ? "#1f0a0a" : "#0a1f0a",
              border: `1px solid ${result.verdict === "MALICIOUS" ? "#7f1d1d" : "#14532d"}`,
              borderRadius: "16px",
              padding: "1.5rem",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}>
              <div>
                <p style={{ color: "#6b7280", fontSize: "0.8rem", margin: "0 0 0.25rem" }}>Scanned file</p>
                <p style={{ color: "white", fontWeight: "700", fontSize: "1.1rem", margin: 0 }}>{result.extension_name}</p>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "2rem" }}>{result.verdict === "MALICIOUS" ? "❌" : "✅"}</div>
                <p style={{
                  color: result.verdict === "MALICIOUS" ? "#f87171" : "#4ade80",
                  fontWeight: "700",
                  margin: "0.25rem 0 0",
                  fontSize: "1rem",
                }}>
                  {result.verdict}
                </p>
              </div>
            </div>

            {/* Risk Score */}
            <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.5rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
                <span style={{ color: "#9ca3af", fontSize: "0.875rem" }}>Risk Score</span>
                <div style={{ textAlign: "right" }}>
                  <span style={{ color: getRiskColor(result.risk_score), fontWeight: "800", fontSize: "1.75rem" }}>
                    {result.risk_score}
                  </span>
                  <span style={{ color: "#4b5563", fontSize: "1rem" }}>/100</span>
                  <span style={{ marginLeft: "0.5rem", color: getRiskColor(result.risk_score), fontSize: "0.8rem", fontWeight: "600" }}>
                    {getRiskLabel(result.risk_score)}
                  </span>
                </div>
              </div>
              <div style={{ background: "#1f2937", borderRadius: "999px", height: "10px", overflow: "hidden" }}>
                <div style={{
                  width: `${result.risk_score}%`,
                  height: "100%",
                  background: getRiskColor(result.risk_score),
                  borderRadius: "999px",
                  transition: "width 0.5s ease",
                }} />
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", marginTop: "0.4rem" }}>
                <span style={{ color: "#374151", fontSize: "0.75rem" }}>Safe</span>
                <span style={{ color: "#374151", fontSize: "0.75rem" }}>Dangerous</span>
              </div>
            </div>

            {/* Confidence */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.25rem", textAlign: "center" }}>
                <p style={{ color: "#6b7280", fontSize: "0.8rem", margin: "0 0 0.25rem" }}>Benign confidence</p>
                <p style={{ color: "#4ade80", fontWeight: "800", fontSize: "1.75rem", margin: 0 }}>{result.confidence_benign}%</p>
              </div>
              <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.25rem", textAlign: "center" }}>
                <p style={{ color: "#6b7280", fontSize: "0.8rem", margin: "0 0 0.25rem" }}>Malicious confidence</p>
                <p style={{ color: "#f87171", fontWeight: "800", fontSize: "1.75rem", margin: 0 }}>{result.confidence_malicious}%</p>
              </div>
            </div>

            {/* Dangerous Permissions */}
            {result.dangerous_permissions.length > 0 && (
              <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.25rem" }}>
                <p style={{ color: "#f87171", fontWeight: "600", fontSize: "0.875rem", margin: "0 0 0.75rem" }}>
                  ⚠️ Dangerous permissions ({result.dangerous_permissions.length})
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                  {result.dangerous_permissions.map((p, i) => (
                    <span key={i} style={{ background: "#1f0a0a", border: "1px solid #7f1d1d", color: "#fca5a5", padding: "4px 10px", borderRadius: "6px", fontSize: "0.8rem" }}>
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Suspicious Patterns */}
            {result.suspicious_patterns.length > 0 && (
              <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.25rem" }}>
                <p style={{ color: "#fbbf24", fontWeight: "600", fontSize: "0.875rem", margin: "0 0 0.75rem" }}>
                  🔎 Suspicious code patterns
                </p>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {result.suspicious_patterns.map((p, i) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", background: "#1a1a24", borderRadius: "8px", padding: "8px 12px" }}>
                      <span style={{ color: "#d1d5db", fontSize: "0.875rem" }}>{p.pattern}</span>
                      <span style={{ color: "#fbbf24", fontWeight: "700", fontSize: "0.875rem" }}>{p.count}×</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* JS Files */}
            {result.js_files.length > 0 && (
              <div style={{ background: "#111118", border: "1px solid #1f2937", borderRadius: "16px", padding: "1.25rem" }}>
                <p style={{ color: "#60a5fa", fontWeight: "600", fontSize: "0.875rem", margin: "0 0 0.75rem" }}>
                  📄 JS files scanned ({result.js_files.length})
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                  {result.js_files.map((f, i) => (
                    <span key={i} style={{ background: "#0f172a", border: "1px solid #1e3a5f", color: "#93c5fd", padding: "4px 10px", borderRadius: "6px", fontSize: "0.8rem" }}>
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Scan Again */}
            <button
              onClick={() => { setResult(null); setError(""); setFileName(""); }}
              style={{ background: "#1d2030", border: "1px solid #2d3748", color: "#9ca3af", padding: "0.75rem", borderRadius: "12px", cursor: "pointer", fontSize: "0.875rem", fontWeight: "600", marginTop: "0.5rem" }}
            >
              ↩ Scan another extension
            </button>

          </div>
        )}
      </div>
    </main>
  );
}