import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:get/get.dart';

import '../../common.dart';
import '../../models/platform_model.dart';

class ServerProfileStatus {
  final String source;
  final int statusNum;
  final String idServer;
  final String relayServer;
  final String apiServer;
  final String revision;

  const ServerProfileStatus({
    required this.source,
    required this.statusNum,
    required this.idServer,
    required this.relayServer,
    required this.apiServer,
    required this.revision,
  });

  bool get isManaged => source == 'provisioned' || source == 'waiting';

  factory ServerProfileStatus.fromJson(String value) {
    final json = jsonDecode(value) as Map<String, dynamic>;
    return ServerProfileStatus(
      source: json['source'] as String? ?? 'public',
      statusNum: json['status_num'] as int? ?? 0,
      idServer: json['id_server'] as String? ?? '',
      relayServer: json['relay_server'] as String? ?? '',
      apiServer: json['api_server'] as String? ?? '',
      revision: json['revision'] as String? ?? '',
    );
  }
}

Future<ServerProfileStatus?> getServerProfileStatus() async {
  if (!isAndroid) return null;
  try {
    return ServerProfileStatus.fromJson(
        await bind.mainGetServerProfileStatus());
  } catch (e) {
    debugPrint('Invalid server profile status: $e');
    return null;
  }
}

String serverProfileConnectionLabel(ServerProfileStatus status,
    {int? statusNum}) {
  if (status.source == 'waiting') return translate('Waiting');
  statusNum ??= status.statusNum;
  if (statusNum > 0) return translate('Ready');
  if (statusNum == 0) return translate('Connecting...');
  return translate('Not ready');
}

void _showSuccess() {
  showToast(translate("Successful"));
}

void setTemporaryPasswordLengthDialog(
    OverlayDialogManager dialogManager) async {
  List<String> lengths = ['6', '8', '10'];
  String length = await bind.mainGetOption(key: "temporary-password-length");
  var index = lengths.indexOf(length);
  if (index < 0) index = 0;
  length = lengths[index];
  dialogManager.show((setState, close, context) {
    setLength(newValue) {
      final oldValue = length;
      if (oldValue == newValue) return;
      setState(() {
        length = newValue;
      });
      bind.mainSetOption(key: "temporary-password-length", value: newValue);
      bind.mainUpdateTemporaryPassword();
      Future.delayed(Duration(milliseconds: 200), () {
        close();
        _showSuccess();
      });
    }

    return CustomAlertDialog(
      title: Text(translate("Set one-time password length")),
      content: Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: lengths
              .map(
                (value) => Row(
                  children: [
                    Text(value),
                    Radio(
                        value: value, groupValue: length, onChanged: setLength),
                  ],
                ),
              )
              .toList()),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}

void showServerSettings(
    OverlayDialogManager dialogManager, void Function(VoidCallback) setState,
    {ServerProfileStatus? serverProfileStatus}) async {
  serverProfileStatus ??= await getServerProfileStatus();
  if (serverProfileStatus?.isManaged == true) {
    _showManagedServerSettings(dialogManager, serverProfileStatus!);
    return;
  }
  Map<String, dynamic> options = {};
  try {
    options = jsonDecode(await bind.mainGetOptions());
  } catch (e) {
    print("Invalid server config: $e");
  }
  String? managedApiServer;
  if (isDesktop) {
    try {
      final status = jsonDecode(await bind.mainGetDesktopManagementStatus());
      if (status is Map<String, dynamic> &&
          status['enrolled'] == true &&
          status['enabled'] == true) {
        managedApiServer = status['api_server']?.toString() ?? '';
      }
    } catch (e) {
      print("Invalid desktop management status: $e");
    }
  }
  showServerSettingsWithValue(
      ServerConfig.fromOptions(options), dialogManager, setState,
      managedApiServer: managedApiServer);
}

void _showManagedServerSettings(
    OverlayDialogManager dialogManager, ServerProfileStatus status) {
  Widget valueRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          SelectableText(value.isEmpty ? '-' : value),
        ],
      ),
    );
  }

  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('ID/Relay Server')),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 280, maxWidth: 500),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${translate('Managed by administrator')} · ${translate('Read-only')}',
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 8),
            Text(serverProfileConnectionLabel(status)),
            valueRow(translate('ID Server'), status.idServer),
            valueRow(translate('Relay Server'), status.relayServer),
            valueRow(translate('API Server'), status.apiServer),
            if (status.revision.isNotEmpty)
              valueRow(translate('Policy revision'), status.revision),
          ],
        ),
      ),
      actions: [
        dialogButton('Close', onPressed: close),
      ],
    );
  });
}

void showServerSettingsWithValue(ServerConfig serverConfig,
    OverlayDialogManager dialogManager, void Function(VoidCallback)? upSetState,
    {String? managedApiServer}) async {
  var isInProgress = false;
  final idCtrl = TextEditingController(text: serverConfig.idServer);
  final relayCtrl = TextEditingController(text: serverConfig.relayServer);
  final apiCtrl =
      TextEditingController(text: managedApiServer ?? serverConfig.apiServer);
  final keyCtrl = TextEditingController(text: serverConfig.key);

  RxString idServerMsg = ''.obs;
  RxString relayServerMsg = ''.obs;
  RxString apiServerMsg = ''.obs;

  final controllers = [idCtrl, relayCtrl, apiCtrl, keyCtrl];
  final errMsgs = [
    idServerMsg,
    relayServerMsg,
    apiServerMsg,
  ];

  dialogManager.show((setState, close, context) {
    Future<bool> submit() async {
      setState(() {
        isInProgress = true;
      });
      bool ret = await setServerConfig(
          null,
          errMsgs,
          ServerConfig(
              idServer: idCtrl.text.trim(),
              relayServer: relayCtrl.text.trim(),
              apiServer: managedApiServer == null
                  ? apiCtrl.text.trim()
                  : serverConfig.apiServer,
              key: keyCtrl.text.trim()));
      setState(() {
        isInProgress = false;
      });
      return ret;
    }

    Widget buildField(
        String label, TextEditingController controller, String errorMsg,
        {String? Function(String?)? validator,
        bool autofocus = false,
        bool enabled = true}) {
      if (isDesktop || isWeb) {
        return Row(
          children: [
            SizedBox(
              width: 120,
              child: Text(label),
            ),
            SizedBox(width: 8),
            Expanded(
              child: serverSettingsTextFormField(
                label: label,
                controller: controller,
                errorMsg: errorMsg,
                contentPadding:
                    EdgeInsets.symmetric(horizontal: 8, vertical: 12),
                showLabelText: false,
                validator: validator,
                autofocus: autofocus,
                enabled: enabled,
              ).workaroundFreezeLinuxMint(),
            ),
          ],
        );
      }

      return serverSettingsTextFormField(
        label: label,
        controller: controller,
        errorMsg: errorMsg,
        validator: validator,
        enabled: enabled,
      ).workaroundFreezeLinuxMint();
    }

    return CustomAlertDialog(
      title: Row(
        children: [
          Expanded(child: Text(translate('ID/Relay Server'))),
          ...ServerConfigImportExportWidgets(controllers, errMsgs),
        ],
      ),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 500),
        child: Form(
          child: Obx(() => Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  buildField(translate('ID Server'), idCtrl, idServerMsg.value,
                      autofocus: true),
                  SizedBox(height: 8),
                  if (!isIOS && !isWeb) ...[
                    buildField(translate('Relay Server'), relayCtrl,
                        relayServerMsg.value),
                    SizedBox(height: 8),
                  ],
                  buildField(
                    translate('API Server'),
                    apiCtrl,
                    apiServerMsg.value,
                    enabled: managedApiServer == null,
                    validator: (v) {
                      if (v != null && v.isNotEmpty) {
                        if (!(v.startsWith('http://') ||
                            v.startsWith("https://"))) {
                          return translate("invalid_http");
                        }
                      }
                      return null;
                    },
                  ),
                  SizedBox(height: 8),
                  buildField('Key', keyCtrl, ''),
                  if (isInProgress)
                    Padding(
                      padding: EdgeInsets.only(top: 8),
                      child: LinearProgressIndicator(),
                    ),
                ],
              )),
        ),
      ),
      actions: [
        dialogButton('Cancel', onPressed: () {
          close();
        }, isOutline: true),
        dialogButton(
          'OK',
          onPressed: () async {
            if (await submit()) {
              close();
              showToast(translate('Successful'));
              upSetState?.call(() {});
            } else {
              showToast(translate('Failed'));
            }
          },
        ),
      ],
    );
  });
}

TextFormField serverSettingsTextFormField({
  required String label,
  required TextEditingController controller,
  required String errorMsg,
  String? Function(String?)? validator,
  bool autofocus = false,
  bool showLabelText = true,
  bool enabled = true,
  EdgeInsetsGeometry? contentPadding,
}) {
  return TextFormField(
    controller: controller,
    decoration: InputDecoration(
      labelText: showLabelText ? label : null,
      errorText: errorMsg.isEmpty ? null : errorMsg,
      contentPadding: contentPadding,
    ),
    validator: validator,
    autofocus: autofocus,
    enabled: enabled,
    keyboardType: TextInputType.visiblePassword,
    textCapitalization: TextCapitalization.none,
    autocorrect: false,
    enableSuggestions: false,
    smartDashesType: SmartDashesType.disabled,
    smartQuotesType: SmartQuotesType.disabled,
    enableIMEPersonalizedLearning: false,
    spellCheckConfiguration: const SpellCheckConfiguration.disabled(),
  );
}

void setPrivacyModeDialog(
  OverlayDialogManager dialogManager,
  List<TToggleMenu> privacyModeList,
  RxString privacyModeState,
) async {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('Privacy mode')),
      content: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: privacyModeList
              .map((value) => CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    visualDensity: VisualDensity.compact,
                    title: value.child,
                    value: value.value,
                    onChanged: value.onChanged,
                  ))
              .toList()),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}
