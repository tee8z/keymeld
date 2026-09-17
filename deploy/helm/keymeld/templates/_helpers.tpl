{{/*
Expand the name of the chart.
*/}}
{{- define "keymeld.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "keymeld.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "keymeld.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keymeld.labels" -}}
helm.sh/chart: {{ include "keymeld.chart" . }}
{{ include "keymeld.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keymeld.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keymeld.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "keymeld.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keymeld.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the gateway image name
Supports both flat structure (image.repository) and nested structure (image.gateway.repository)
*/}}
{{- define "keymeld.image" -}}
{{- if .Values.image.gateway -}}
{{- $tag := default .Chart.AppVersion .Values.image.gateway.tag -}}
{{- printf "%s:%s" .Values.image.gateway.repository $tag -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Return the enclave image name
Supports both enclave.image structure and image.enclave structure
*/}}
{{- define "keymeld.enclaveImage" -}}
{{- if .Values.image.enclave -}}
{{- $tag := default .Chart.AppVersion .Values.image.enclave.tag -}}
{{- printf "%s:%s" .Values.image.enclave.repository $tag -}}
{{- else if .Values.enclave.image -}}
{{- $tag := default .Chart.AppVersion .Values.enclave.image.tag -}}
{{- printf "%s:%s" .Values.enclave.image.repository $tag -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s-enclave:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Return the image pull policy for gateway
*/}}
{{- define "keymeld.imagePullPolicy" -}}
{{- if .Values.image.gateway -}}
{{- .Values.image.gateway.pullPolicy | default "IfNotPresent" -}}
{{- else -}}
{{- .Values.image.pullPolicy | default "IfNotPresent" -}}
{{- end -}}
{{- end }}

{{/*
Return the image pull policy for enclave
*/}}
{{- define "keymeld.enclaveImagePullPolicy" -}}
{{- if .Values.image.enclave -}}
{{- .Values.image.enclave.pullPolicy | default "IfNotPresent" -}}
{{- else if .Values.enclave.image -}}
{{- .Values.enclave.image.pullPolicy | default "IfNotPresent" -}}
{{- else -}}
{{- .Values.image.pullPolicy | default "IfNotPresent" -}}
{{- end -}}
{{- end }}
