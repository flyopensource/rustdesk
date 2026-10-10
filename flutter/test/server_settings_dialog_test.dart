import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/mobile/widgets/dialog.dart';

ServerProfileStatus managedStatus({
  bool configured = true,
  String source = 'provisioned',
  int statusNum = 1,
  bool permanentPasswordSet = true,
  bool unattendedEnabled = false,
  String unattendedStatus = '',
  bool rootAvailable = false,
  bool screenCaptureReady = false,
  bool accessibilityReady = false,
  bool allFilesAccessReady = false,
  bool serviceRunning = false,
}) {
  return ServerProfileStatus(
    configured: configured,
    source: source,
    statusNum: statusNum,
    idServer: 'id.example.com',
    relayServer: 'relay.example.com',
    apiServer: 'https://api.example.com',
    revision: '1',
    permanentPasswordSet: permanentPasswordSet,
    unattendedEnabled: unattendedEnabled,
    unattendedStatus: unattendedStatus,
    rootAvailable: rootAvailable,
    screenCaptureReady: screenCaptureReady,
    accessibilityReady: accessibilityReady,
    allFilesAccessReady: allFilesAccessReady,
    serviceRunning: serviceRunning,
    lastError: '',
  );
}

void main() {
  test('Android server profile status includes managed and manual routes', () {
    final status = ServerProfileStatus.fromJson('''
      {
        "configured": true,
        "source": "manual",
        "use_managed_server_profile": false,
        "managed_id_server": "managed.example:21116",
        "managed_relay_server": "managed.example:21117",
        "managed_key": "managed-key",
        "manual_id_server": "manual.example:21116",
        "manual_relay_server": "manual.example:21117",
        "manual_key": "manual-key"
      }
    ''');

    expect(status.useManagedServerProfile, isFalse);
    expect(status.managedIdServer, 'managed.example:21116');
    expect(status.managedRelayServer, 'managed.example:21117');
    expect(status.managedKey, 'managed-key');
    expect(status.manualIdServer, 'manual.example:21116');
    expect(status.manualRelayServer, 'manual.example:21117');
    expect(status.manualKey, 'manual-key');
  });

  testWidgets('server settings text fields preserve literal input',
      (tester) async {
    final controller = TextEditingController(text: 'AbCdR1c1E=');
    addTearDown(controller.dispose);

    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: serverSettingsTextFormField(
          label: 'Key',
          controller: controller,
          errorMsg: '',
          autofocus: true,
        ),
      ),
    ));

    final textField = tester.widget<TextField>(find.byType(TextField));

    expect(textField.controller, controller);
    expect(textField.autofocus, isTrue);
    expect(textField.keyboardType, TextInputType.visiblePassword);
    expect(textField.textCapitalization, TextCapitalization.none);
    expect(textField.autocorrect, isFalse);
    expect(textField.enableSuggestions, isFalse);
    expect(textField.smartDashesType, SmartDashesType.disabled);
    expect(textField.smartQuotesType, SmartQuotesType.disabled);
    expect(textField.enableIMEPersonalizedLearning, isFalse);
    expect(
      textField.spellCheckConfiguration,
      const SpellCheckConfiguration.disabled(),
    );
  });

  test('Android remote configuration summary uses actual session state', () {
    expect(
      androidRemoteConfigurationState(
        managedStatus(configured: false, source: 'public'),
        activeSessions: 0,
      ),
      AndroidRemoteConfigurationState.notConfigured,
    );
    expect(
      androidRemoteConfigurationState(
        managedStatus(configured: false, source: 'public'),
        activeSessions: 1,
      ),
      AndroidRemoteConfigurationState.remoteControlInProgress,
    );
    final notConfigured = managedStatus(source: 'not_configured');
    expect(notConfigured.isManaged, isTrue);
    expect(
      androidRemoteConfigurationState(
        notConfigured,
        activeSessions: 0,
      ),
      AndroidRemoteConfigurationState.notConfigured,
    );
    expect(
      androidRemoteConfigurationState(
        managedStatus(statusNum: -1),
        activeSessions: 0,
      ),
      AndroidRemoteConfigurationState.connectionIssue,
    );
    expect(
      androidRemoteConfigurationState(
        managedStatus(permanentPasswordSet: false),
        activeSessions: 0,
      ),
      AndroidRemoteConfigurationState.partiallyReady,
    );
    expect(
      androidRemoteConfigurationState(
        managedStatus(
          unattendedEnabled: true,
          unattendedStatus: 'partial',
        ),
        activeSessions: 0,
      ),
      AndroidRemoteConfigurationState.partiallyReady,
    );
    expect(
      androidRemoteConfigurationState(managedStatus(), activeSessions: 0),
      AndroidRemoteConfigurationState.ready,
    );
  });
}
