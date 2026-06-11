# Regenerate the model-derived test corpus from the Scryer Prolog model.
#
#   make corpus     # regenerate tests/corpus/iscsi_model_corpus.txt
#   make check      # regenerate to a temp file and diff against the committed corpus
#
# Requires scryer-prolog on PATH (cargo install scryer-prolog).

SCRYER ?= scryer-prolog
MODEL  := iscsi_protocol.pl
CORPUS := ../tests/corpus/iscsi_model_corpus.txt

.PHONY: corpus check

corpus:
	$(SCRYER) -g emit_corpus -g halt $(MODEL) > $(CORPUS)
	@echo "Wrote $(CORPUS)"

check:
	@$(SCRYER) -g emit_corpus -g halt $(MODEL) > /tmp/iscsi_model_corpus.gen.txt
	@diff $(CORPUS) /tmp/iscsi_model_corpus.gen.txt \
		&& echo "OK: committed corpus matches the model" \
		|| (echo "DRIFT: run 'make corpus' to regenerate"; exit 1)
