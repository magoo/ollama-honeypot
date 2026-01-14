# Ollama-Honeypot

`ollama-honeypot` is a python script designed to capture and record malicious probes from internet scans looking for exposed ollama llm instances.

Normally, `ollama` listens to `http://127.0.0.1:11434` on localhost, but can be exposed to the internet by setting the environment variable `OLLAMA_HOST` to `0.0.0.0`. This is a vulnerable configuration that we hope to capture with a python script.

`ollama-honeypot` will safely output all requests to STDOUT in single line format and will sanitize any output so that it can be echo'd to the system.

A configuration file `ollama-honeypot.conf` will contain basic configuration options.

`ollama-honeypot.responses` will include responses the honeypot llm will use to respond to malicious queries.
