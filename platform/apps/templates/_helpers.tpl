{{/*
Git refs whose build-image.yml signatures the platform trusts, as a regexp group: main, plus the branch
the platform is deployed from when it is not main (environment-specific trust, see docs/THREAT-MODEL.md).
*/}}
{{- define "harborlab.trustedRefs" -}}
{{- if eq .Values.revision "main" -}}
main
{{- else -}}
(main|{{ regexQuoteMeta .Values.revision }})
{{- end -}}
{{- end -}}
