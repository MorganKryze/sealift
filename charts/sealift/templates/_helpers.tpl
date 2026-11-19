{{/* sealift.value takes (list "<key>" <value>) and returns the value, or fails naming the key. */}}
{{- define "sealift.value" -}}
{{- $key := index . 0 -}}
{{- $v := index . 1 -}}
{{- if not $v -}}
{{- fail (printf "%s is required" $key) -}}
{{- end -}}
{{- $s := toString $v -}}
{{- if regexMatch "<[^<>]+>" $s -}}
{{- fail (printf "%s still holds its placeholder %s" $key (regexFind "<[^<>]+>" $s)) -}}
{{- end -}}
{{- $s -}}
{{- end -}}

{{- define "sealift.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sealift.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "sealift.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "sealift.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sealift.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sealift.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sealift.publicKeyConfigMap" -}}
{{- if .Values.publicKey.existingConfigMap -}}
{{- .Values.publicKey.existingConfigMap -}}
{{- else -}}
{{- printf "%s-public-key" (include "sealift.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "sealift.caConfigMap" -}}
{{- if .Values.ca.existingConfigMap -}}
{{- .Values.ca.existingConfigMap -}}
{{- else -}}
{{- printf "%s-ca" (include "sealift.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "sealift.claimName" -}}
{{- default (include "sealift.fullname" .) .Values.persistence.existingClaim -}}
{{- end -}}

{{/* sealift.publicKeySHA256 is the fingerprint the service shows: the sha256 of the key's DER encoding. */}}
{{- define "sealift.publicKeySHA256" -}}
{{- regexReplaceAll "-----[A-Z ]+-----|\\s" .Values.publicKey.pem "" | b64dec | sha256sum -}}
{{- end -}}
