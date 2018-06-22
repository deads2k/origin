/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package get

import (
	"github.com/spf13/cobra"

	"k8s.io/kubernetes/pkg/kubectl/genericclioptions"
	"k8s.io/kubernetes/pkg/printers"
)

// KubeTemplatePrintFlags composes print flags that provide both a JSONPath and a go-template printer.
// This is necessary if dealing with cases that require support both both printers, since both sets of flags
// require overlapping flags.
type KubeTemplatePrintFlags struct {
	*printers.GoTemplatePrintFlags
	*printers.JSONPathPrintFlags

	AllowMissingKeys *bool
	TemplateArgument *string
}

func (f *KubeTemplatePrintFlags) AllowedFormats() []string {
	return append(f.GoTemplatePrintFlags.AllowedFormats(), f.JSONPathPrintFlags.AllowedFormats()...)
}

func (f *KubeTemplatePrintFlags) ToPrinter(outputFormat string) (printers.ResourcePrinter, error) {
	// for "get.go" we want to support a --template argument given, even when no --output format is provided
	if f.TemplateArgument != nil && len(*f.TemplateArgument) > 0 && len(outputFormat) == 0 {
		outputFormat = "go-template"
	}

	if p, err := f.JSONPathPrintFlags.ToPrinter(outputFormat); !genericclioptions.IsNoCompatiblePrinterError(err) {
		return p, err
	}
	return f.GoTemplatePrintFlags.ToPrinter(outputFormat)
}

// AddFlags receives a *cobra.Command reference and binds
// flags related to template printing to it
func (f *KubeTemplatePrintFlags) AddFlags(c *cobra.Command) {
	if f.TemplateArgument != nil {
		c.Flags().StringVar(f.TemplateArgument, "template", *f.TemplateArgument, "Template string or path to template file to use when -o=go-template, -o=go-template-file. The template format is golang templates [http://golang.org/pkg/text/template/#pkg-overview].")
		c.MarkFlagFilename("template")
	}
	if f.AllowMissingKeys != nil {
		c.Flags().BoolVar(f.AllowMissingKeys, "allow-missing-template-keys", *f.AllowMissingKeys, "If true, ignore any errors in templates when a field or map key is missing in the template. Only applies to golang and jsonpath output formats.")
	}
}

// NewKubeTemplatePrintFlags returns flags associated with
// --template printing, with default values set.
func NewKubeTemplatePrintFlags() *KubeTemplatePrintFlags {
	allowMissingKeysPtr := true
	templateArgPtr := ""

	return &KubeTemplatePrintFlags{
		GoTemplatePrintFlags: &printers.GoTemplatePrintFlags{
			TemplateArgument: &templateArgPtr,
			AllowMissingKeys: &allowMissingKeysPtr,
		},
		JSONPathPrintFlags: &printers.JSONPathPrintFlags{
			TemplateArgument: &templateArgPtr,
			AllowMissingKeys: &allowMissingKeysPtr,
		},

		TemplateArgument: &templateArgPtr,
		AllowMissingKeys: &allowMissingKeysPtr,
	}
}
