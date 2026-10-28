PY ?= python3
starter:   ; $(PY) run.py all --profile starter
full:      ; $(PY) run.py all --profile full
test:      ; $(PY) -m unittest discover -s tests -v
serve:   ; $(PY) run.py serve --profile full --port 8080
demo:    ; $(PY) run.py demo --profile full
clean:     ; rm -rf output
