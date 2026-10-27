/*
Copyright 2026.

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

package consumerportal

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/opendatahub-io/ai-gateway-controller/pkg/render"
	"github.com/opendatahub-io/ai-gateway-controller/pkg/tenant"
)

func renderTestResources(t *testing.T) map[string]unstructured.Unstructured {
	t.Helper()
	built, err := render.Build(testManifestPath)
	if err != nil {
		t.Fatalf("render.Build: %v", err)
	}
	resources := Render(built, Params{
		Namespace:             testInfraNamespace,
		DashboardNamespace:    testDashboardNamespace,
		Image:                 "quay.io/example/kube-auth-proxy:test",
		OIDCIssuerURL:         testIssuer,
		Hostname:              testHostname,
		GatewayName:           testGatewayName,
		GatewayNamespace:      testGatewayNamespace,
		AuthorinoNamespace:    DefaultAuthorinoNamespace,
		DashboardServiceReady: true,
	})
	byName := map[string]unstructured.Unstructured{}
	for _, u := range resources {
		byName[u.GetKind()+"/"+u.GetName()] = u
	}
	return byName
}

func TestRenderSubstitutesTenantValues(t *testing.T) {
	resources := renderTestResources(t)
	for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "NetworkPolicy"} {
		u, ok := resources[kind+"/"+AuthProxyName]
		if !ok {
			t.Fatalf("rendered resources missing %s", kind)
		}
		if u.GetNamespace() != testInfraNamespace || u.GetName() != AuthProxyName {
			t.Errorf("%s = %s/%s, want %s/%s", kind, u.GetNamespace(), u.GetName(), testInfraNamespace, AuthProxyName)
		}
		if u.GetLabels()[tenant.LabelManagedBy] != tenant.ManagedByAIGatewayController {
			t.Errorf("%s missing managed-by label: %v", kind, u.GetLabels())
		}
		raw, err := json.Marshal(u.Object)
		if err != nil {
			t.Fatalf("marshal %s: %v", kind, err)
		}
		if strings.Contains(string(raw), "CONSUMER_PORTAL_") {
			t.Errorf("%s still contains an unreplaced token: %s", kind, raw)
		}
	}

	deployment := resources["Deployment/"+AuthProxyName]
	containers, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	if len(containers) != 1 {
		t.Fatalf("Deployment containers = %d, want 1", len(containers))
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatalf("container is not an object: %#v", containers[0])
	}
	if container["image"] != "quay.io/example/kube-auth-proxy:test" {
		t.Errorf("image = %v", container["image"])
	}
	args, _, _ := unstructured.NestedStringSlice(container, "args")
	for _, want := range []string{
		"--provider=oidc",
		"--oidc-issuer-url=" + testIssuer,
		"--redirect-url=https://" + testHostname + "/oauth2/callback",
		"--cookie-domain=" + testHostname,
		"--https-address=0.0.0.0:4180",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("auth proxy args missing %q: %v", want, args)
		}
	}

	policy := resources["NetworkPolicy/"+AuthProxyName]
	raw, err := json.Marshal(policy.Object)
	if err != nil {
		t.Fatalf("marshal NetworkPolicy: %v", err)
	}
	for _, want := range []string{testGatewayNamespace, testGatewayName, DefaultAuthorinoNamespace} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("NetworkPolicy does not reference %q: %s", want, raw)
		}
	}
}

func TestRenderRoutesGrantAndBackendTLS(t *testing.T) {
	resources := renderTestResources(t)

	portalRoute := resources["HTTPRoute/"+PortalRouteName]
	if portalRoute.GetNamespace() != testInfraNamespace {
		t.Errorf("portal HTTPRoute namespace = %q, want %q", portalRoute.GetNamespace(), testInfraNamespace)
	}
	if hostnames, _, _ := unstructured.NestedStringSlice(portalRoute.Object, "spec", "hostnames"); len(hostnames) != 1 || hostnames[0] != testHostname {
		t.Errorf("portal hostnames = %v, want [%s]", hostnames, testHostname)
	}
	parents, _, _ := unstructured.NestedSlice(portalRoute.Object, "spec", "parentRefs")
	parent, ok := parents[0].(map[string]any)
	if !ok {
		t.Fatalf("portal parentRef is not an object: %#v", parents[0])
	}
	if parent["name"] != testGatewayName || parent["namespace"] != testGatewayNamespace {
		t.Errorf("portal parentRef = %#v", parent)
	}
	rules, _, _ := unstructured.NestedSlice(portalRoute.Object, "spec", "rules")
	if len(rules) != 2 {
		t.Fatalf("portal rules = %d, want 2", len(rules))
	}
	redirectRule, _ := rules[0].(map[string]any)
	redirectFilter, _ := redirectRule["filters"].([]any)[0].(map[string]any)
	if redirectFilter["type"] != "RequestRedirect" {
		t.Errorf("bare path filter = %#v, want RequestRedirect", redirectFilter)
	}
	backendRule, _ := rules[1].(map[string]any)
	backendRef, _ := backendRule["backendRefs"].([]any)[0].(map[string]any)
	if backendRef["name"] != DashboardServiceName || backendRef["namespace"] != testDashboardNamespace || backendRef["port"] != int64(8443) {
		t.Errorf("portal backendRef = %#v", backendRef)
	}
	rewriteFilter, _ := backendRule["filters"].([]any)[0].(map[string]any)
	if rewriteFilter["type"] != "URLRewrite" {
		t.Errorf("portal path filter = %#v, want URLRewrite", rewriteFilter)
	}

	oauthRoute := resources["HTTPRoute/"+OAuth2RouteName]
	oauthRules, _, _ := unstructured.NestedSlice(oauthRoute.Object, "spec", "rules")
	oauthBackend, _ := oauthRules[0].(map[string]any)["backendRefs"].([]any)[0].(map[string]any)
	if oauthBackend["name"] != AuthProxyName || oauthBackend["port"] != int64(4180) {
		t.Errorf("OAuth backendRef = %#v", oauthBackend)
	}

	referenceGrant := resources["ReferenceGrant/"+PortalRouteName]
	if referenceGrant.GetNamespace() != testDashboardNamespace {
		t.Errorf("ReferenceGrant namespace = %q, want %q", referenceGrant.GetNamespace(), testDashboardNamespace)
	}
	from, _, _ := unstructured.NestedSlice(referenceGrant.Object, "spec", "from")
	fromRoute, _ := from[0].(map[string]any)
	if fromRoute["namespace"] != testInfraNamespace {
		t.Errorf("ReferenceGrant from = %#v", fromRoute)
	}

	proxyTLS := resources["DestinationRule/"+AuthProxyBackendTLSName]
	if proxyTLS.GetNamespace() != testGatewayNamespace {
		t.Errorf("proxy DestinationRule namespace = %q, want %q", proxyTLS.GetNamespace(), testGatewayNamespace)
	}
	if host, _, _ := unstructured.NestedString(proxyTLS.Object, "spec", "host"); host != AuthProxyName+"."+testInfraNamespace+".svc.cluster.local" {
		t.Errorf("proxy DestinationRule host = %q", host)
	}
	portalTLS := resources["DestinationRule/"+PortalBackendTLSName]
	if host, _, _ := unstructured.NestedString(portalTLS.Object, "spec", "host"); host != DashboardServiceName+"."+testDashboardNamespace+".svc.cluster.local" {
		t.Errorf("portal DestinationRule host = %q", host)
	}
}

func TestRenderAuthPolicies(t *testing.T) {
	resources := renderTestResources(t)

	anonymous := resources["AuthPolicy/"+OAuth2AnonymousAuthPolicyName]
	if anonymous.GetNamespace() != testInfraNamespace {
		t.Errorf("anonymous AuthPolicy namespace = %q, want %q", anonymous.GetNamespace(), testInfraNamespace)
	}
	if target, _, _ := unstructured.NestedString(anonymous.Object, "spec", "targetRef", "name"); target != OAuth2RouteName {
		t.Errorf("anonymous targetRef name = %q, want %q", target, OAuth2RouteName)
	}
	if _, found, _ := unstructured.NestedMap(anonymous.Object, "spec", "rules", "authentication", "public-login", "anonymous"); !found {
		t.Error("anonymous AuthPolicy does not enable anonymous authentication")
	}

	session := resources["AuthPolicy/"+PortalSessionAuthPolicyName]
	if target, _, _ := unstructured.NestedString(session.Object, "spec", "targetRef", "name"); target != PortalRouteName {
		t.Errorf("session targetRef name = %q, want %q", target, PortalRouteName)
	}
	rego, _, _ := unstructured.NestedString(session.Object,
		"spec", "rules", "authorization", "session", "opa", "rego")
	proxyURL := "https://" + AuthProxyName + "." + testInfraNamespace + ".svc.cluster.local:4180/oauth2/auth"
	for _, want := range []string{
		`"url": "` + proxyURL + `"`,
		`object.get(input.context.request.http.headers, "cookie", "")`,
		`"headers": {"Cookie": cookie}`,
		`"tls_ca_cert_file": "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"`,
		`"timeout": "2s"`,
		`"cache": false`,
		`"enable_redirect": false`,
		`"raise_error": false`,
		`login_location := sprintf("/oauth2/start?rd=%s", [urlquery.encode(input.context.request.http.path)])`,
	} {
		if !strings.Contains(rego, want) {
			t.Errorf("session Rego missing %q:\n%s", want, rego)
		}
	}

	forwardedValue, _, _ := unstructured.NestedString(session.Object,
		"spec", "rules", "response", "success", "headers", "x-forwarded-access-token", "plain", "expression")
	if forwardedValue != "auth.authorization.session.identity.access_token" {
		t.Errorf("x-forwarded-access-token expression = %q", forwardedValue)
	}
	if code, _, _ := unstructured.NestedInt64(session.Object,
		"spec", "rules", "response", "unauthorized", "code"); code != 302 {
		t.Errorf("unauthorized code = %d, want 302", code)
	}
	location, _, _ := unstructured.NestedString(session.Object,
		"spec", "rules", "response", "unauthorized", "headers", "Location", "expression")
	if location != "auth.authorization.session.login_location" {
		t.Errorf("unauthorized Location expression = %q", location)
	}
	cacheControl, _, _ := unstructured.NestedString(session.Object,
		"spec", "rules", "response", "unauthorized", "headers", "Cache-Control", "value")
	if cacheControl != "no-store" {
		t.Errorf("unauthorized Cache-Control = %q, want no-store", cacheControl)
	}
}

func TestRenderOmitsPortalResourcesUntilDashboardServiceExists(t *testing.T) {
	built, err := render.Build(testManifestPath)
	if err != nil {
		t.Fatalf("render.Build: %v", err)
	}
	resources := Render(built, Params{
		Namespace:          testInfraNamespace,
		DashboardNamespace: testDashboardNamespace,
		Hostname:           testHostname,
		GatewayName:        testGatewayName,
		GatewayNamespace:   testGatewayNamespace,
	})
	for _, key := range []string{
		"HTTPRoute/" + PortalRouteName,
		"ReferenceGrant/" + PortalRouteName,
		"DestinationRule/" + PortalBackendTLSName,
		"AuthPolicy/" + PortalSessionAuthPolicyName,
	} {
		for _, resource := range resources {
			if resource.GetKind()+"/"+resource.GetName() == key {
				t.Errorf("dashboard Service missing but %s was rendered", key)
			}
		}
	}
	foundOAuthRoute := false
	foundProxyTLS := false
	foundAnonymousPolicy := false
	for _, resource := range resources {
		if resource.GetKind()+"/"+resource.GetName() == "HTTPRoute/"+OAuth2RouteName {
			foundOAuthRoute = true
		}
		if resource.GetKind()+"/"+resource.GetName() == "DestinationRule/"+AuthProxyBackendTLSName {
			foundProxyTLS = true
		}
		if resource.GetKind()+"/"+resource.GetName() == "AuthPolicy/"+OAuth2AnonymousAuthPolicyName {
			foundAnonymousPolicy = true
		}
	}
	if !foundOAuthRoute || !foundProxyTLS || !foundAnonymousPolicy {
		t.Errorf("OAuth route = %v, proxy TLS = %v, anonymous policy = %v; all should render",
			foundOAuthRoute, foundProxyTLS, foundAnonymousPolicy)
	}
}

func TestListenerHostname(t *testing.T) {
	cases := map[string]struct {
		listeners []map[string]any
		want      string
	}{
		"https listener": {listeners: []map[string]any{httpsListener(testHostname)}, want: testHostname},
		"skips wildcard and http": {listeners: []map[string]any{
			httpsListener("*.apps.example.com"),
			{"name": "http", "protocol": "HTTP", "hostname": "plain.example.com"},
			httpsListener(testHostname),
		}, want: testHostname},
		"no hostname": {listeners: []map[string]any{{"name": "https", "protocol": "HTTPS"}}, want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ListenerHostname(newGateway(tc.listeners...)); got != tc.want {
				t.Errorf("ListenerHostname = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPortalEnabledDefaultsTrue(t *testing.T) {
	if !PortalEnabled(newAITenant(aitenantOpts{})) {
		t.Error("consumer portal should default to enabled")
	}
	if PortalEnabled(newAITenant(aitenantOpts{portalDisabled: true})) {
		t.Error("consumerPortal.enabled=false was ignored")
	}
}

func TestRenderAddsProviderCAFilesPerKey(t *testing.T) {
	built, err := render.Build(testManifestPath)
	if err != nil {
		t.Fatalf("render.Build: %v", err)
	}
	argsFor := func(keys []string) []string {
		for _, u := range Render(built, Params{Namespace: testInfraNamespace, ProviderCAKeys: keys}) {
			if u.GetKind() != "Deployment" {
				continue
			}
			containers, _, _ := unstructured.NestedSlice(u.Object, "spec", "template", "spec", "containers")
			container, ok := containers[0].(map[string]any)
			if !ok {
				t.Fatalf("container is not an object: %#v", containers[0])
			}
			args, _, _ := unstructured.NestedStringSlice(container, "args")
			return args
		}
		t.Fatal("no Deployment rendered")
		return nil
	}

	if args := argsFor([]string{"ca-bundle.crt"}); !slices.Contains(args, "--provider-ca-file=/etc/pki/odh-trusted-ca/ca-bundle.crt") ||
		slices.Contains(args, "--provider-ca-file=/etc/pki/odh-trusted-ca/odh-ca-bundle.crt") {
		t.Errorf("args for [ca-bundle.crt] = %v", args)
	}
	for _, arg := range argsFor(nil) {
		if strings.HasPrefix(arg, "--provider-ca-file=") {
			t.Errorf("unexpected %q without CA keys", arg)
		}
	}
}

func TestRenderSetsCABundleHashAnnotation(t *testing.T) {
	built, err := render.Build(testManifestPath)
	if err != nil {
		t.Fatalf("render.Build: %v", err)
	}
	params := Params{
		Namespace:    testInfraNamespace,
		CABundleHash: "ca-bundle-hash",
	}
	deployment := unstructured.Unstructured{}
	for _, u := range Render(built, params) {
		if u.GetKind() == "Deployment" {
			deployment = u
			break
		}
	}
	hash, _, _ := unstructured.NestedString(deployment.Object,
		"spec", "template", "metadata", "annotations", CABundleHashAnnotation)
	if hash != "ca-bundle-hash" {
		t.Errorf("CA bundle hash annotation = %q, want ca-bundle-hash", hash)
	}

	params.CABundleHash = ""
	for _, u := range Render(built, params) {
		if u.GetKind() != "Deployment" {
			continue
		}
		hash, found, _ := unstructured.NestedString(u.Object,
			"spec", "template", "metadata", "annotations", CABundleHashAnnotation)
		if found || hash != "" {
			t.Errorf("empty CA bundle hash rendered annotation %q", hash)
		}
	}
}
