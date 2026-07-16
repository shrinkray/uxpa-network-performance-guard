(function ($) {
    "use strict";

    const config = window.uxpaNetworkGuard || {};
    const i18n = config.i18n || {};

    function escapeHtml(value) {
        return $("<div>").text(value || "").html();
    }

    function sortTable(table, columnIndex, type, asc) {
        const tbody = table.querySelector("tbody");
        const rows = Array.from(tbody.querySelectorAll("tr"));

        if (rows.length <= 1 && $(rows[0]).find("td").length <= 1) {
            return;
        }

        rows.sort((a, b) => {
            const valA = a.cells[columnIndex] ? a.cells[columnIndex].innerText.trim() : "";
            const valB = b.cells[columnIndex] ? b.cells[columnIndex].innerText.trim() : "";

            if (type === "ip") {
                const ipToNum = (ip) => {
                    const clean = ip.replace(/[^0-9.]/g, "").split(".");
                    if (clean.length !== 4) {
                        return null;
                    }
                    return clean.reduce((acc, octet) => (acc * 256) + parseInt(octet, 10), 0);
                };
                const numA = ipToNum(valA);
                const numB = ipToNum(valB);
                if (numA === null || numB === null) {
                    return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
                }
                return asc ? numA - numB : numB - numA;
            }

            if (type === "number") {
                const numA = parseFloat(valA.replace(/[^0-9.-]/g, "")) || 0;
                const numB = parseFloat(valB.replace(/[^0-9.-]/g, "")) || 0;
                return asc ? numA - numB : numB - numA;
            }

            if (type === "date") {
                const dateA = new Date(valA.replace(/-/g, "/")).getTime() || 0;
                const dateB = new Date(valB.replace(/-/g, "/")).getTime() || 0;
                return asc ? dateA - dateB : dateB - dateA;
            }

            return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
        });

        tbody.innerHTML = "";
        rows.forEach((row) => tbody.appendChild(row));
    }

    function buildStatusHtml(edgeBlocked, hostBlocked) {
        if (!edgeBlocked && !hostBlocked) {
            return '<span class="badge cf-active-badge">' + escapeHtml(i18n.loggedActive) + "</span>";
        }

        let html = '<div class="block-status-badges">';
        if (edgeBlocked) {
            html += '<span class="badge cf-blocked-badge">' + escapeHtml(i18n.blockedAtEdge) + "</span>";
        }
        if (hostBlocked) {
            html += '<span class="badge host-blocked-badge">' + escapeHtml(i18n.blockedAtHost) + "</span>";
        }
        return html + "</div>";
    }

    function buildActionsHtml(ip, edgeBlocked, hostBlocked) {
        const edgeBtnClass = edgeBlocked ? "button button-secondary" : "button button-primary-outline";
        const edgeBtnText = escapeHtml(edgeBlocked ? i18n.removeEdgeBlock : i18n.markEdgeBlock);
        const hostBtnClass = hostBlocked ? "button button-secondary" : "button button-primary-outline";
        const hostBtnText = escapeHtml(hostBlocked ? i18n.removeHostBlock : i18n.markHostBlock);
        const escapedIp = escapeHtml(ip);

        return '<div class="block-actions">' +
            '<button type="button" class="uxpa-toggle-cloudflare ' + edgeBtnClass + '" data-ip="' + escapedIp + '">' + edgeBtnText + "</button>" +
            '<button type="button" class="uxpa-toggle-webhost ' + hostBtnClass + '" data-ip="' + escapedIp + '">' + hostBtnText + "</button>" +
            "</div>";
    }

    function updateCopyAssistant(type, blockedIps) {
        const prefix = type === "host" ? "host" : "cf";
        const textarea = $("#" + prefix + "-blocked-list-text");
        const badge = $("#" + prefix + "-blocked-count-badge");
        const emptyMsg = $("#" + prefix + "-empty-msg");
        const copyBtn = $("#copy-" + prefix + "-list");

        if (!textarea.length) {
            return;
        }

        textarea.val(blockedIps.join("\n"));
        badge.text(blockedIps.length);

        if (blockedIps.length === 0) {
            emptyMsg.removeClass("is-hidden");
            textarea.addClass("is-hidden");
            copyBtn.addClass("is-hidden");
        } else {
            emptyMsg.addClass("is-hidden");
            textarea.removeClass("is-hidden");
            copyBtn.removeClass("is-hidden");
        }
    }

    function refreshBlockUI(edgeBlockedIps, hostBlockedIps) {
        $("tr").each(function () {
            const row = $(this);
            if (!row.find(".block-status-cell").length) {
                return;
            }

            const ipCode = row.find("code.ip-address");
            if (!ipCode.length) {
                return;
            }

            const ip = ipCode.text().trim();
            const edgeBlocked = edgeBlockedIps.indexOf(ip) !== -1;
            const hostBlocked = hostBlockedIps.indexOf(ip) !== -1;

            row.find(".block-status-cell").html(buildStatusHtml(edgeBlocked, hostBlocked));
            row.find("td:has(.block-actions)").html(buildActionsHtml(ip, edgeBlocked, hostBlocked));
            row.toggleClass("row-ip-blocked", edgeBlocked || hostBlocked);
            if (!edgeBlocked && !hostBlocked) {
                row.removeClass("row-cf-blocked");
            }
        });

        updateCopyAssistant("cf", edgeBlockedIps);
        updateCopyAssistant("host", hostBlockedIps);
    }

    function handleBlockToggle(button, action) {
        const ip = button.data("ip");
        const row = button.closest("tr");
        const controls = row.find(".block-actions .button");

        controls.prop("disabled", true).addClass("updating");

        $.post(config.ajaxUrl, {
            action,
            ip,
            nonce: config.nonce
        }).done((response) => {
            if (response.success) {
                refreshBlockUI(response.data.edge_blocked_ips, response.data.webhost_blocked_ips);
            } else {
                window.alert(response.data.message || i18n.errorOccurred);
            }
        }).fail(() => {
            window.alert(i18n.requestFailed);
        }).always(() => {
            controls.prop("disabled", false).removeClass("updating");
        });
    }

    function showCopied(button) {
        const originalHtml = button.html();
        button.html('<span class="dashicons dashicons-yes"></span> ' + i18n.copied).addClass("button-success");
        window.setTimeout(() => {
            button.html(originalHtml).removeClass("button-success");
        }, 2000);
    }

    $(function () {
        $("th.sortable").on("click", function () {
            const th = $(this);
            const table = th.closest("table")[0];
            const asc = !th.hasClass("asc");

            th.closest("tr").find("th").removeClass("asc desc");
            th.addClass(asc ? "asc" : "desc");
            sortTable(table, th.index(), th.data("type") || "string", asc);
        });

        $(document).on("click", ".uxpa-toggle-cloudflare", function (event) {
            event.preventDefault();
            handleBlockToggle($(this), "uxpa_toggle_cloudflare_blocked");
        });

        $(document).on("click", ".uxpa-toggle-webhost", function (event) {
            event.preventDefault();
            handleBlockToggle($(this), "uxpa_toggle_webhost_blocked");
        });

        $(document).on("click", "#copy-cf-list, #copy-host-list", function () {
            const button = $(this);
            const listId = button.attr("id") === "copy-host-list"
                ? "host-blocked-list-text"
                : "cf-blocked-list-text";
            const textarea = document.getElementById(listId);

            textarea.select();
            textarea.setSelectionRange(0, 99999);

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(textarea.value)
                    .then(() => showCopied(button))
                    .catch(() => {
                        try {
                            document.execCommand("copy");
                            showCopied(button);
                        } catch (error) {
                            window.alert(i18n.copyFailed);
                        }
                    });
                return;
            }

            try {
                document.execCommand("copy");
                showCopied(button);
            } catch (error) {
                window.alert(i18n.copyFailed);
            }
        });
    });
})(jQuery);
