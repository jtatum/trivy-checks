package trivy_checks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Execute the shipped audit commands against controlled process listings. A Rego
// fixture alone cannot catch collection failures: the collector sanitizes a
// shell self-match to an empty value before the policy ever sees it.
func TestNodeAuditProcessSelection(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("audit commands require a POSIX shell")
	}

	commands := []struct {
		name, binary, flag, value, statFormat string
	}{
		{"kubeletAnonymousAuthArgumentSet", "kubelet", "--anonymous-auth", "false", ""},
		{"kubeletAuthorizationModeArgumentSet", "kubelet", "--authorization-mode", "Webhook", ""},
		{"kubeletClientCaFileArgumentSet", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", ""},
		{"kubeletEventQpsArgumentSet", "kubelet", "--event-qps", "0", ""},
		{"kubeletHostnameOverrideArgumentSet", "kubelet", "--hostname-override", "node-01", ""},
		{"kubeletMakeIptablesUtilChainsArgumentSet", "kubelet", "--make-iptables-util-chains", "true", ""},
		{"kubeletOnlyUseStrongCryptographic", "kubelet", "--TLSCipherSuites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ""},
		{"kubeletProtectKernelDefaultsArgumentSet", "kubelet", "--protect-kernel-defaults", "true", ""},
		{"kubeletReadOnlyPortArgumentSet", "kubelet", "--read-only-port", "0", ""},
		{"kubeletRotateCertificatesArgumentSet", "kubelet", "--rotate-certificates", "true", ""},
		{"kubeletRotateKubeletServerCertificateArgumentSet", "kubelet", "--feature-gates=RotateKubeletServerCertificate", "true", ""},
		{"kubeletStreamingConnectionIdleTimeoutArgumentSet", "kubelet", "--streamingConnectionIdleTimeout", "5m", ""},
		{"kubeletTlsCertFileTlsArgumentSet", "kubelet", "--tls-cert-file", "/etc/kubernetes/kubelet.crt", ""},
		{"kubeletTlsPrivateKeyFileArgumentSet", "kubelet", "--tls-private-key-file", "/etc/kubernetes/kubelet.key", ""},
		{"certificateAuthoritiesFileOwnership", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", "%U:%G"},
		{"certificateAuthoritiesFilePermissions", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", "%a"},
		{"kubeconfigFileExistsOwnership", "kube-proxy", "--kubeconfig", "/etc/kubernetes/proxy.conf", "%U:%G"},
		{"kubeconfigFileExistsPermissions", "kube-proxy", "--kubeconfig", "/etc/kubernetes/proxy.conf", "%a"},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			data, err := EmbeddedK8sCommandsFileSystem.ReadFile("commands/kubernetes/" + command.name + ".yaml")
			require.NoError(t, err)
			var definitions []struct{ Audit string }
			require.NoError(t, yaml.Unmarshal(data, &definitions))
			require.Len(t, definitions, 1)
			audit := strings.NewReplacer("$kubelet.bins", "kubelet", "$proxy.bins", "kube-proxy").Replace(definitions[0].Audit)
			// This is the shell process the collector starts with exec.Command("sh", "-c", audit).
			self := "/bin/sh -c " + audit
			process := "/usr/local/bin/" + command.binary + " " + command.flag + "=" + command.value
			unrelated := "/usr/bin/" + command.binary + "-helper " + command.flag + "=wrong"

			cases := []struct {
				name      string
				processes []string
				want      string
			}{
				{"shell_before_target", []string{self, process}, command.value},
				{"target_before_shell", []string{process, self}, command.value},
				{"unrelated_binary_before_target", []string{unrelated, self, process}, command.value},
				{"binary_name_only_in_arguments", []string{"/bin/echo /usr/local/bin/" + command.binary + " " + command.flag + "=wrong", self, process}, command.value},
				{"target_without_flag", []string{self, "/usr/local/bin/" + command.binary}, ""},
				{"target_absent", []string{unrelated, self}, ""},
				{"only_shell", []string{self}, ""},
				{"bare_executable_name", []string{self, command.binary + " " + command.flag + "=" + command.value}, command.value},
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					dir := t.TempDir()
					fixture := filepath.Join(dir, "processes")
					require.NoError(t, os.WriteFile(fixture, []byte(strings.Join(tt.processes, "\n")+"\n"), 0600))
					// Support both the original ps -ef and the corrected args-only listing
					// so this test can demonstrate the failure before the fix.
					ps := `#!/bin/sh
case "$*" in
  '-ef') awk '{printf "%d root 0:00 %s\n", NR + 100, $0}' "$AUDIT_TEST_PROCESSES" ;;
  '-eo args') cat "$AUDIT_TEST_PROCESSES" ;;
  *) exit 2 ;;
esac
`
					require.NoError(t, os.WriteFile(filepath.Join(dir, "ps"), []byte(ps), 0700))
					statArgs := filepath.Join(dir, "stat-args")
					// Record the selected path without inspecting files on the test host.
					stat := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AUDIT_TEST_STAT_ARGS\"\nprintf 'root:root\\n'\n"
					require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0700))
					cmd := exec.Command("sh", "-c", audit)
					cmd.Env = append(os.Environ(),
						"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
						"AUDIT_TEST_PROCESSES="+fixture,
						"AUDIT_TEST_STAT_ARGS="+statArgs,
					)
					output, err := cmd.CombinedOutput()
					require.NoError(t, err, "%s", output)
					if command.statFormat != "" {
						args, err := os.ReadFile(statArgs)
						require.NoError(t, err)
						want := fmt.Sprintf("-c\n%s\n", command.statFormat)
						if tt.want != "" {
							want += tt.want + "\n"
						}
						require.Equal(t, want, string(args))
					} else {
						require.Equal(t, tt.want, strings.TrimSpace(string(output)))
					}
				})
			}
		})
	}
}
