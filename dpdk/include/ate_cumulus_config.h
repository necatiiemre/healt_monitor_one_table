/**
 * @file ate_cumulus_config.h
 * @brief ATE Test Mode - Cumulus Switch Configuration via SSH
 *
 * DPDK sunucusundan (10.1.33.2) dogrudan Cumulus switch'e (10.1.33.3)
 * SSH ile ATE test modu icin yeni interfaces ve bridge VLAN config gonderir.
 *
 * C++ tarafindaki CumulusHelper + SSHDeployer mekanizmasinin
 * C karsiligi olarak calisir.
 *
 * Kullanim:
 *   if (ate_configure_cumulus() == 0) {
 *       printf("ATE Cumulus config basarili!\n");
 *   }
 */

#ifndef ATE_CUMULUS_CONFIG_H
#define ATE_CUMULUS_CONFIG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==========================================
// CUMULUS SSH CREDENTIALS
// ==========================================
#define ATE_CUMULUS_HOST        "10.1.33.3"
#define ATE_CUMULUS_USER        "cumulus"
#define ATE_CUMULUS_PASSWORD    "%T86Ovk7RCH%h@CC"

// ==========================================
// ATE INTERFACES FILE PATH
// ==========================================
// Sunucuda DPDK deploy dizininde bulunur
#define ATE_INTERFACES_LOCAL_PATH   "/home/user/Desktop/dpdk/ate_cumulus/interfaces"
#define ATE_INTERFACES_REMOTE_PATH  "/etc/network/interfaces"

// ==========================================
// API
// ==========================================

/**
 * @brief Test SSH connection to Cumulus switch
 * @return true on success
 */
bool ate_cumulus_test_connection(void);

/**
 * @brief Deploy ATE interfaces file to Cumulus switch
 *
 * 1. SCP ile interfaces dosyasini /tmp/interfaces olarak gonderir
 * 2. sudo mv /tmp/interfaces /etc/network/interfaces
 * 3. sudo ifreload -a
 *
 * @return true on success
 */
bool ate_cumulus_deploy_interfaces(void);

/**
 * @brief Run ATE VLAN configuration sequence on Cumulus switch
 *
 * CumulusHelper::configureSequence() mantigi ile
 * sudo bridge vlan add dev swpXXsY vid VV untagged komutlarini calistirir.
 *
 * @return true on success
 */
bool ate_cumulus_configure_sequence(void);

/**
 * @brief Full ATE Cumulus configuration (deploy + configure)
 *
 * 1. Test connection
 * 2. Deploy ATE interfaces file
 * 3. Run bridge VLAN configuration sequence
 *
 * @return 0 on success, -1 on failure
 */
int ate_configure_cumulus(void);

// ==========================================
// LOW-LEVEL HELPERS
// ==========================================

/**
 * @brief Execute command on Cumulus via SSH
 * @param command Remote command to execute
 * @param use_sudo Run with sudo
 * @return true on success (exit code 0)
 */
bool ate_cumulus_ssh_execute(const char *command, bool use_sudo);

/**
 * @brief Copy file to Cumulus via SCP
 * @param local_path Local file path
 * @param remote_path Remote file path
 * @return true on success
 */
bool ate_cumulus_scp_copy(const char *local_path, const char *remote_path);

/**
 * @brief Add bridge VLAN untagged to interface on Cumulus
 *
 * Runs: sudo bridge vlan add dev <interface> vid <vlan_id> untagged
 *
 * @param interface Switch port name (e.g., "swp25s0")
 * @param vlan_id VLAN ID
 * @return true on success
 */
bool ate_cumulus_egress_untagged(const char *interface, int vlan_id);

#ifdef __cplusplus
}
#endif

#endif // ATE_CUMULUS_CONFIG_H
