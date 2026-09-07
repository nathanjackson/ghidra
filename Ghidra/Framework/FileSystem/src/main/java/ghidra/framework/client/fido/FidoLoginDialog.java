/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.framework.client.fido;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.NameCallback;
import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.remote.FidoAuthenticationCallback;
import ghidra.util.MessageType;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;

/**
 * Modal FIDO2 login dialog. OK starts the platform helper on a worker thread;
 * the dialog does not open a browser.
 */
public class FidoLoginDialog extends DialogComponentProvider {

	static final String TOUCH_STATUS = "Touch your security key";

	private final NameCallback nameCb;
	private final FidoAuthenticationCallback fidoCb;
	private final FidoAuthenticator authenticator;
	private final FidoAllowCredentialsLookup allowLookup;
	private final boolean allowUserNameEntry;

	private JTextField nameField;
	private JPasswordField pinField;
	private JTextField enrollTokenField;

	private final AtomicBoolean cancelled = new AtomicBoolean();
	private final AtomicBoolean finished = new AtomicBoolean();
	private final AtomicBoolean helperRunning = new AtomicBoolean();

	private volatile Thread workerThread;
	private boolean okPressed;
	private IOException failure;

	/**
	 * @param nameCb name callback; null means the default user name is used
	 * @param fidoCb FIDO2 callback to fill
	 * @param serverName Ghidra Server name shown in the dialog
	 * @param authenticator helper used to complete assertion or enrollment
	 * @param allowLookup per-username allow-list lookup; may be null
	 * @param loginError previous login error to display, or null
	 */
	public FidoLoginDialog(NameCallback nameCb, FidoAuthenticationCallback fidoCb,
			String serverName, FidoAuthenticator authenticator,
			FidoAllowCredentialsLookup allowLookup, String loginError) {
		super("Ghidra Server FIDO Sign-In", true);
		if (fidoCb == null) {
			throw new IllegalArgumentException("fidoCb is required");
		}
		if (authenticator == null) {
			throw new IllegalArgumentException("authenticator is required");
		}
		this.nameCb = nameCb;
		this.fidoCb = fidoCb;
		this.authenticator = authenticator;
		this.allowLookup = allowLookup;
		this.allowUserNameEntry = nameCb != null;

		setRememberSize(false);
		setTransient(true);
		setAccessibleDescription(
			"Sign in to the Ghidra Server with a FIDO2 security key. Do not open a browser.");

		createWorkPanel(serverName);
		addOKButton();
		addCancelButton();
		setOkEnabled(true);
		if (nameField != null) {
			setFocusComponent(nameField);
		}
		else {
			setFocusComponent(pinField);
		}
		if (!StringUtils.isBlank(loginError)) {
			setStatusText(loginError, MessageType.ERROR);
		}
	}

	private void createWorkPanel(String serverName) {
		JPanel workPanel = new JPanel(new PairLayout(5, 5));
		workPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

		if (serverName != null) {
			workPanel.add(new GLabel("Server:"));
			workPanel.add(new GLabel(serverName));
		}

		String defaultUser = defaultUserName();
		workPanel.add(new GLabel("User ID:"));
		if (allowUserNameEntry) {
			nameField = new JTextField(defaultUser, 16);
			nameField.setName("NAME-ENTRY-COMPONENT");
			nameField.getAccessibleContext().setAccessibleName("User ID");
			workPanel.add(nameField);
		}
		else {
			JLabel nameLabel = new GLabel(defaultUser == null ? "" : defaultUser);
			nameLabel.setName("NAME-COMPONENT");
			nameLabel.getAccessibleContext().setAccessibleName("User ID");
			workPanel.add(nameLabel);
		}

		workPanel.add(new GLabel("Key PIN:"));
		pinField = new JPasswordField(16);
		pinField.setName("FIDO-PIN");
		pinField.getAccessibleContext().setAccessibleName("Security key PIN");
		pinField.setToolTipText("PIN for the security key. Leave blank if the key has no PIN.");
		workPanel.add(pinField);

		workPanel.add(new GLabel("Enroll token:"));
		enrollTokenField = new JTextField(16);
		enrollTokenField.setName("ENROLL-TOKEN");
		enrollTokenField.getAccessibleContext()
				.setAccessibleName("Optional enrollment token");
		enrollTokenField.setToolTipText("Leave blank to sign in. Paste an admin enroll token to register a new security key.");
		workPanel.add(enrollTokenField);

		workPanel.getAccessibleContext().setAccessibleName("FIDO Sign-In");
		addWorkPanel(workPanel);
	}

	private String defaultUserName() {
		if (nameCb == null) {
			return ClientUtil.getUserName();
		}
		String name = nameCb.getName();
		if (StringUtils.isBlank(name)) {
			name = nameCb.getDefaultName();
		}
		if (StringUtils.isBlank(name)) {
			return ClientUtil.getUserName();
		}
		return name;
	}

	@Override
	protected void okCallback() {
		if (helperRunning.get() || finished.get()) {
			return;
		}
		String userName = currentUserName();
		if (StringUtils.isBlank(userName)) {
			setStatusText("User ID is required", MessageType.ERROR);
			return;
		}
		String enrollToken = currentEnrollToken();
		char[] pin = pinField.getPassword();
		setOkEnabled(false);
		if (nameField != null) {
			nameField.setEnabled(false);
		}
		pinField.setEnabled(false);
		enrollTokenField.setEnabled(false);
		setStatusText(TOUCH_STATUS);
		helperRunning.set(true);
		Thread t = new Thread(() -> runHelper(userName, enrollToken, pin), "FIDO Helper");
		t.setDaemon(true);
		workerThread = t;
		t.start();
	}

	private void runHelper(String userName, String enrollToken, char[] pin) {
		try {
			if (cancelled.get()) {
				Swing.runNow(this::finishCancelled);
				return;
			}
			byte[][] allow = allowCredentials(userName);
			if (cancelled.get()) {
				Swing.runNow(this::finishCancelled);
				return;
			}
			authenticator.complete(fidoCb, userName, enrollToken, allow, pin);
			if (nameCb != null) {
				nameCb.setName(userName);
			}
			Swing.runNow(this::finishSuccess);
		}
		catch (IOException e) {
			if (cancelled.get()) {
				Swing.runNow(this::finishCancelled);
				return;
			}
			Swing.runNow(() -> finishHelperError(e));
		}
		finally {
			if (pin != null) {
				Arrays.fill(pin, '\0');
			}
		}
	}

	private byte[][] allowCredentials(String userName) throws IOException {
		if (allowLookup != null) {
			byte[][] ids = allowLookup.getAllowCredentials(userName);
			if (ids != null) {
				return ids;
			}
		}
		byte[][] fromCb = fidoCb.getAllowCredentials();
		return fromCb == null ? new byte[0][] : fromCb;
	}

	private void finishSuccess() {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		okPressed = true;
		helperRunning.set(false);
		clearPinField();
		close();
	}

	private void finishCancelled() {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		helperRunning.set(false);
		clearPinField();
		close();
	}

	private void finishHelperError(IOException e) {
		helperRunning.set(false);
		failure = e;
		String msg = e.getMessage();
		if (StringUtils.isBlank(msg)) {
			msg = "FIDO helper failed";
		}
		setStatusText(msg, MessageType.ERROR);
		setOkEnabled(true);
		if (nameField != null) {
			nameField.setEnabled(true);
		}
		pinField.setEnabled(true);
		enrollTokenField.setEnabled(true);
	}

	private void clearPinField() {
		if (pinField != null) {
			pinField.setText("");
		}
	}

	@Override
	protected void cancelCallback() {
		cancelled.set(true);
		authenticator.cancel();
		Thread t = workerThread;
		if (t != null) {
			t.interrupt();
		}
		finishCancelled();
	}

	@Override
	protected void dialogClosed() {
		cancelled.set(true);
		authenticator.cancel();
	}

	@Override
	public void close() {
		closeDialog();
	}

	@Override
	public void dispose() {
		cancelled.set(true);
		authenticator.cancel();
		clearPinField();
		super.dispose();
	}

	/**
	 * {@return true if the helper completed and filled the callback}
	 */
	public boolean okWasPressed() {
		return okPressed;
	}

	/**
	 * {@return helper failure, or null if cancelled or successful}
	 */
	public IOException getFailure() {
		return failure;
	}

	JTextField getNameField() {
		return nameField;
	}

	JPasswordField getPinField() {
		return pinField;
	}

	JTextField getEnrollTokenField() {
		return enrollTokenField;
	}

	String currentUserName() {
		if (nameField != null) {
			return nameField.getText().trim();
		}
		return defaultUserName().trim();
	}

	String currentEnrollToken() {
		String token = enrollTokenField.getText();
		return token == null ? "" : token.trim();
	}

	void waitForWorker() throws InterruptedException {
		Thread t = workerThread;
		if (t == null) {
			return;
		}
		t.join(30_000);
		if (t.isAlive()) {
			throw new InterruptedException("FIDO dialog worker did not finish");
		}
	}
}
