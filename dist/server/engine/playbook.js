export const PLAYBOOK = {
    block_ip: {
        title: 'Block source IP at the host firewall',
        target: 'ip',
        risk: 'low',
        reversible: true,
        command: (ip) => `sudo ufw insert 1 deny from ${ip} to any`,
    },
    rate_limit_ssh: {
        title: 'Rate-limit SSH connections',
        target: 'none',
        risk: 'low',
        reversible: true,
        command: () => 'sudo ufw limit 22/tcp',
    },
    disable_password_auth: {
        title: 'Disable SSH password authentication (keys only)',
        target: 'none',
        risk: 'medium',
        reversible: true,
        command: () => "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
    },
    lock_account: {
        title: 'Lock the affected account',
        target: 'user',
        risk: 'medium',
        reversible: true,
        command: (user) => `sudo usermod -L ${user} && sudo chage -E 0 ${user}`,
    },
    terminate_sessions: {
        title: 'Terminate active sessions for the account',
        target: 'user',
        risk: 'medium',
        reversible: false,
        command: (user) => `sudo pkill -KILL -u ${user}`,
    },
    force_password_reset: {
        title: 'Force a password reset at next login',
        target: 'user',
        risk: 'low',
        reversible: true,
        command: (user) => `sudo passwd --expire ${user}`,
    },
    remove_unauthorized_account: {
        title: 'Remove the unauthorised account',
        target: 'user',
        risk: 'high',
        reversible: false,
        command: (user) => `sudo userdel --remove ${user}`,
    },
    review_sudoers: {
        title: 'Audit sudo rights and privileged groups',
        target: 'none',
        risk: 'low',
        reversible: true,
        command: () => 'sudo visudo -c && sudo grep -rv "^#" /etc/sudoers.d/ && getent group sudo wheel',
    },
    add_waf_rule: {
        title: 'Block the source at the WAF / reverse proxy',
        target: 'ip',
        risk: 'low',
        reversible: true,
        command: (ip) => `# nginx: add to the server block, then reload\ndeny ${ip};`,
    },
    patch_web_app: {
        title: 'Fix the vulnerable input handling in the web app',
        target: 'none',
        risk: 'low',
        reversible: true,
        command: () => '# Use parameterised queries / output encoding; re-test the affected endpoints',
    },
    preserve_evidence: {
        title: 'Preserve logs as forensic evidence',
        target: 'none',
        risk: 'low',
        reversible: true,
        command: () => 'sudo tar czf /root/ir-evidence-$(date +%Y%m%d%H%M).tgz /var/log',
    },
    escalate_to_human: {
        title: 'Escalate to the incident-response lead',
        target: 'none',
        risk: 'low',
        reversible: true,
        command: () => '# Page the on-call incident-response lead with this report',
    },
};
export const PLAYBOOK_IDS = Object.keys(PLAYBOOK);
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$/;
const USERNAME = /^[a-z_][a-z0-9_-]{0,31}$/;
export function isValidIp(value) {
    return IPV4.test(value) || IPV6.test(value);
}
export function isValidUsername(value) {
    return USERNAME.test(value);
}
export function targetKind(action) {
    return PLAYBOOK[action].target;
}
/**
 * Builds a concrete action. Returns null when the action needs a target that
 * is missing or fails validation (so it can never yield an unsafe command).
 */
export function buildAction(id, incidentId, action, rationale, target) {
    const entry = PLAYBOOK[action];
    let safeTarget;
    if (entry.target === 'ip') {
        if (!target || !isValidIp(target))
            return null;
        safeTarget = target;
    }
    else if (entry.target === 'user') {
        if (!target || !isValidUsername(target))
            return null;
        safeTarget = target;
    }
    const built = {
        id,
        incidentId,
        action,
        title: entry.title,
        rationale: rationale.slice(0, 400),
        command: entry.command(safeTarget ?? ''),
        risk: entry.risk,
        reversible: entry.reversible,
    };
    if (safeTarget)
        built.target = safeTarget;
    return built;
}
