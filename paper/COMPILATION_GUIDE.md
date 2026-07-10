# GMCP-R Protocol: LaTeX Compilation Guide

## Overview

This guide explains how to compile the GMCP-R paper from LaTeX source to PDF.

## Prerequisites

### Required Software

1. **TeX Distribution**: TeX Live or MiKTeX
2. **Editor**: TeXstudio, VS Code with LaTeX Workshop, or Overleaf
3. **Bibliography**: BibTeX or Biber

### Installation (macOS)

```bash
# Install MacTeX
brew install --cask mactex

# Or install BasicTeX (smaller)
brew install --cask basictex

# Verify installation
pdflatex --version
bibtex --version
```

## File Structure

```
paper/
├── main.tex           # Main LaTeX source
├── references.bib     # Bibliography database
├── figures/           # Figure directory
│   ├── baseline_fig1_recovery_latency.png
│   ├── baseline_fig2_throughput.png
│   ├── baseline_fig3_attack_detection.png
│   ├── baseline_fig4_success_rate_heatmap.png
│   └── baseline_fig5_rtt_distribution.png
└── main.pdf           # Compiled PDF (generated)
```

## Compilation Steps

### Method 1: Command Line

```bash
cd /Users/a0000/Desktop/实验/gmcp_r/paper

# Step 1: First pass
pdflatex main.tex

# Step 2: Bibliography
bibtex main

# Step 3: Second pass
pdflatex main.tex

# Step 4: Third pass (resolve references)
pdflatex main.tex
```

### Method 2: Single Command

```bash
# Using latexmk (recommended)
latexmk -pdf main.tex

# Or with clean
latexmk -c main.tex
```

### Method 3: VS Code with LaTeX Workshop

1. Install LaTeX Workshop extension
2. Open main.tex
3. Press Ctrl+Alt+B to build
4. Press Ctrl+Alt+V to view PDF

## Common Issues

### Issue 1: Missing Figures

**Error**: `! LaTeX Error: File 'figures/xxx.png' not found.`

**Solution**:
```bash
# Copy figures to paper directory
cp -r results/real_baseline_comparison/figures paper/
```

### Issue 2: Bibliography Not Showing

**Error**: `Citation 'xxx' undefined`

**Solution**:
```bash
# Run BibTeX
bibtex main

# Then run pdflatex twice
pdflatex main.tex
pdflatex main.tex
```

### Issue 3: Package Missing

**Error**: `! LaTeX Error: File 'xxx.sty' not found.`

**Solution**:
```bash
# Install missing package
tlmgr install xxx

# Or install all packages
tlmgr install --reinstall collection-latexextra
```

## Template Customization

### IEEE Conference Template

The paper uses IEEEtran class. Key settings:

```latex
\documentclass[conference]{IEEEtran}
```

Options:
- `conference`: Conference format (default)
- `journal`: Journal format
- `10pt`, `11pt`, `12pt`: Font size

### Adding Figures

```latex
\begin{figure}[t]
\centering
\includegraphics[width=\columnwidth]{figures/baseline_fig1_recovery_latency.png}
\caption{Recovery latency comparison across protocols.}
\label{fig:recovery_latency}
\end{figure}
```

### Adding Tables

```latex
\begin{table}[t]
\centering
\caption{Attack Detection Rates}
\begin{tabular}{lcccc}
\toprule
Protocol & Drop & Modify & Replay & prev\_mem \\
\midrule
GMCP-R & 100\% & 100\% & 100\% & 100\% \\
\bottomrule
\end{tabular}
\label{tab:detection_rates}
\end{table}
```

### Cross-References

```latex
Figure~\ref{fig:recovery_latency} shows...
Table~\ref{tab:detection_rates} presents...
Section~\ref{sec:experiments} describes...
```

## Bibliography Management

### Adding References

Edit `references.bib`:

```bibtex
@article{key,
  title={Title},
  author={Author},
  journal={Journal},
  year={2024}
}
```

### Citation Styles

```latex
\cite{key}           % [1]
\cite{key1, key2}    % [1, 2]
\cite[p.~42]{key}    % [1, p. 42]
```

## PDF Optimization

### Reduce File Size

```bash
# Compress PDF
gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dPDFSETTINGS=/ebook \
   -dNOPAUSE -dBATCH -sOutputFile=main_compressed.pdf main.pdf
```

### Add Metadata

```latex
\usepackage{hyperref}
\hypersetup{
    pdftitle={GMCP-R Protocol},
    pdfauthor={Junyu Wang},
    pdfsubject={Secure Communication},
    pdfkeywords={protocol, security, recovery}
}
```

## Submission Checklist

- [ ] All figures included and referenced
- [ ] All citations resolved
- [ ] No compilation errors
- [ ] Page limit respected
- [ ] Author information anonymized (if double-blind)
- [ ] Supplementary material prepared

## Quick Commands

```bash
# Full build
cd /Users/a0000/Desktop/实验/gmcp_r/paper && latexmk -pdf main.tex

# Clean auxiliary files
latexmk -c main.tex

# View PDF
open main.pdf
```

---

**Last Updated**: 2026-07-03
