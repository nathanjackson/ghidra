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
package ghidra.framework.client.oidc;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Font;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.OidcAuthenticationCallback;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * Modal dialog that walks a user through RFC 8628 device-code sign-in. The
 * browser is opened only when the user clicks Open Browser.
 */
public class OidcLoginDialog extends DialogComponentProvider {

	private static final String WAITING_STATUS = "Waiting for authorization...";
	private static final float USER_CODE_FONT_SIZE = 22f;

	private final OidcAuthenticationCallback oidcCb;
	private final OidcDeviceCodeFlow flow;
	private final BrowserOpener browserOpener;

	private JTextField userCodeField;
	private JTextField verificationUriField;
	private JButton openBrowserButton;
	private GCheckBox anonymousAccess;

	private final AtomicBoolean flowStarted = new AtomicBoolean();
	private final AtomicBoolean cancelled = new AtomicBoolean();
	private final AtomicBoolean finished = new AtomicBoolean();
	private final AtomicBoolean anonymousRequested = new AtomicBoolean();

	private volatile Thread workerThread;
	private volatile OidcDeviceCodeFlow.DeviceAuthorization authorization;

	private boolean okPressed;
	private boolean anonymousResult;
	private String idToken;
	private IOException failure;

	/**
	 * Construct a dialog that runs a new device-code flow.
	 *
	 * @param oidcCb OIDC callback with provider metadata
	 * @param anonymousCb anonymous-access callback, or null if the server did not
	 *            offer it
	 * @param serverName Ghidra Server name shown in the dialog
	 * @throws IOException if the HTTP client cannot be created
	 */
	public OidcLoginDialog(OidcAuthenticationCallback oidcCb, AnonymousCallback anonymousCb,
			String serverName) throws IOException {
		this(oidcCb, anonymousCb, serverName, new OidcDeviceCodeFlow(), null);
	}

	OidcLoginDialog(OidcAuthenticationCallback oidcCb, AnonymousCallback anonymousCb,
			String serverName, OidcDeviceCodeFlow flow, BrowserOpener browserOpener) {
		super("Ghidra Server OIDC Sign-In", true);
		if (oidcCb == null) {
			throw new IllegalArgumentException("oidcCb is required");
		}
		if (flow == null) {
			throw new IllegalArgumentException("flow is required");
		}
		this.oidcCb = oidcCb;
		this.flow = flow;
		this.browserOpener = browserOpener != null ? browserOpener : OidcLoginDialog::browseWithDesktop;

		setRememberSize(false);
		setTransient(true);
		setAccessibleDescription(
			"Sign in to the Ghidra Server with your identity provider using a device code.");

		createWorkPanel(serverName, anonymousCb != null);
		openBrowserButton = new GButton("Open Browser");
		openBrowserButton.setName("OPEN-BROWSER");
		openBrowserButton.getAccessibleContext().setAccessibleName("Open Browser");
		openBrowserButton.setEnabled(false);
		openBrowserButton.addActionListener(e -> openBrowser());
		addButton(openBrowserButton);
		addCancelButton();
		setFocusComponent(userCodeField);
	}

	private void createWorkPanel(String serverName, boolean includeAnonymousOption) {
		JPanel workPanel = new JPanel(new BorderLayout(0, 10));
		workPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

		JPanel fields = new JPanel(new PairLayout(5, 5));
		if (serverName != null) {
			fields.add(new GLabel("Server:"));
			fields.add(new GLabel(serverName));
		}

		fields.add(new GLabel("Visit:"));
		verificationUriField = new JTextField(32);
		verificationUriField.setName("VERIFICATION-URI");
		verificationUriField.getAccessibleContext().setAccessibleName("Verification URL");
		verificationUriField.setEditable(false);
		verificationUriField.setFocusable(true);
		fields.add(verificationUriField);

		fields.add(new GLabel("User code:"));
		userCodeField = new JTextField(12);
		userCodeField.setName("USER-CODE");
		userCodeField.getAccessibleContext().setAccessibleName("User code");
		userCodeField.setEditable(false);
		userCodeField.setFocusable(true);
		userCodeField.setHorizontalAlignment(SwingConstants.CENTER);
		Font base = userCodeField.getFont();
		userCodeField.setFont(base.deriveFont(Font.BOLD, USER_CODE_FONT_SIZE));
		fields.add(userCodeField);
		workPanel.add(fields, BorderLayout.NORTH);

		JPanel south = new JPanel(new VerticalLayout(8));
		south.add(new GLabel("Open a browser, enter the code, and sign in."));
		if (includeAnonymousOption) {
			anonymousAccess = new GCheckBox("Request Anonymous Access");
			anonymousAccess.setName("ANONYMOUS-COMPONENT");
			anonymousAccess.getAccessibleContext().setAccessibleName("Request Anonymous Access");
			anonymousAccess.addItemListener(e -> {
				if (anonymousAccess.isSelected()) {
					skipWithAnonymousAccess();
				}
			});
			south.add(anonymousAccess);
		}
		workPanel.add(south, BorderLayout.SOUTH);
		workPanel.getAccessibleContext().setAccessibleName("OIDC Sign-In");
		addWorkPanel(workPanel);
	}

	@Override
	protected void dialogShown() {
		startAuthorization();
	}

	@Override
	protected void dialogClosed() {
		cancelAuthorization();
	}

	@Override
	protected void cancelCallback() {
		cancelAuthorization();
		finishCancelled();
	}

	@Override
	public void close() {
		// Keep fields readable after the modal dialog returns, matching PasswordDialog.
		closeDialog();
	}

	@Override
	public void dispose() {
		cancelAuthorization();
		super.dispose();
	}

	/**
	 * Start the device-code request and poll. One device_code is issued per dialog.
	 */
	void startAuthorization() {
		if (anonymousRequested.get()) {
			finishAnonymous();
			return;
		}
		if (!flowStarted.compareAndSet(false, true)) {
			return;
		}
		setStatusText("Requesting authorization...");
		Thread t = new Thread(this::runDeviceFlow, "OIDC Device Authorization");
		t.setDaemon(true);
		workerThread = t;
		t.start();
	}

	private void runDeviceFlow() {
		try {
			if (anonymousRequested.get() || cancelled.get()) {
				if (anonymousRequested.get()) {
					Swing.runNow(this::finishAnonymous);
				}
				else {
					Swing.runNow(this::finishCancelled);
				}
				return;
			}
			String token = flow.complete(oidcCb, this::onAuthorizationStarted, this::isCancelled);
			if (anonymousRequested.get()) {
				Swing.runNow(this::finishAnonymous);
				return;
			}
			String captured = token;
			Swing.runNow(() -> finishSuccess(captured));
		}
		catch (CancelledException e) {
			if (anonymousRequested.get()) {
				Swing.runNow(this::finishAnonymous);
			}
			else {
				Swing.runNow(this::finishCancelled);
			}
		}
		catch (IOException e) {
			if (anonymousRequested.get()) {
				Swing.runNow(this::finishAnonymous);
				return;
			}
			Swing.runNow(() -> finishFailure(e));
		}
	}

	private void onAuthorizationStarted(OidcDeviceCodeFlow.DeviceAuthorization deviceAuthorization) {
		authorization = deviceAuthorization;
		Swing.runNow(() -> displayAuthorization(deviceAuthorization));
	}

	private void displayAuthorization(OidcDeviceCodeFlow.DeviceAuthorization deviceAuthorization) {
		if (finished.get()) {
			return;
		}
		userCodeField.setText(deviceAuthorization.getUserCode());
		userCodeField.selectAll();
		verificationUriField.setText(nullToEmpty(deviceAuthorization.getVerificationUri()));
		openBrowserButton.setEnabled(browseUri(deviceAuthorization) != null);
		setStatusText(WAITING_STATUS);
	}

	private void openBrowser() {
		OidcDeviceCodeFlow.DeviceAuthorization current = authorization;
		String url = browseUri(current);
		if (url == null) {
			setStatusText("No verification URL is available.", MessageType.ERROR);
			return;
		}
		URI uri;
		try {
			uri = URI.create(url.trim());
		}
		catch (IllegalArgumentException e) {
			setStatusText("Verification URL is not a valid address.", MessageType.ERROR);
			return;
		}
		String scheme = uri.getScheme();
		if (scheme == null ||
			!(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))) {
			setStatusText("Verification URL is not a valid http(s) address.", MessageType.ERROR);
			return;
		}
		try {
			browserOpener.browse(uri);
			setStatusText(WAITING_STATUS);
		}
		catch (Exception e) {
			// Do not log the URL: verification_uri_complete embeds user_code.
			Msg.error(this, "Unable to open a browser for OIDC sign-in");
			setStatusText("Unable to open a browser. Visit the URL shown above.",
				MessageType.ERROR);
		}
	}

	private void skipWithAnonymousAccess() {
		anonymousRequested.set(true);
		cancelAuthorization();
		finishAnonymous();
	}

	private void cancelAuthorization() {
		cancelled.set(true);
		flow.cancel();
		Thread t = workerThread;
		if (t != null) {
			t.interrupt();
		}
	}

	private boolean isCancelled() {
		return cancelled.get() || anonymousRequested.get();
	}

	private void finishSuccess(String token) {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		idToken = token;
		okPressed = true;
		close();
	}

	private void finishAnonymous() {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		anonymousResult = true;
		close();
	}

	private void finishCancelled() {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		close();
	}

	private void finishFailure(IOException e) {
		if (!finished.compareAndSet(false, true)) {
			return;
		}
		failure = e;
		close();
	}

	/**
	 * {@return true if sign-in completed with an ID token}
	 */
	public boolean okWasPressed() {
		return okPressed;
	}

	/**
	 * {@return true if the user requested anonymous access instead of device-code sign-in}
	 */
	public boolean anonymousAccessRequested() {
		return anonymousResult;
	}

	/**
	 * {@return the ID token from a successful poll, or null}
	 */
	public String getIdToken() {
		return idToken;
	}

	/**
	 * {@return a poll or device-authorization failure, or null if cancelled or successful}
	 */
	public IOException getFailure() {
		return failure;
	}

	JTextField getUserCodeField() {
		return userCodeField;
	}

	JTextField getVerificationUriField() {
		return verificationUriField;
	}

	JButton getOpenBrowserButton() {
		return openBrowserButton;
	}

	GCheckBox getAnonymousCheckBox() {
		return anonymousAccess;
	}

	void waitForWorker() throws InterruptedException {
		Thread t = workerThread;
		if (t == null) {
			return;
		}
		t.join(10_000);
		if (t.isAlive()) {
			throw new InterruptedException("OIDC dialog worker did not finish");
		}
	}

	private static String browseUri(OidcDeviceCodeFlow.DeviceAuthorization deviceAuthorization) {
		if (deviceAuthorization == null) {
			return null;
		}
		String complete = deviceAuthorization.getVerificationUriComplete();
		if (!isBlank(complete)) {
			return complete;
		}
		String uri = deviceAuthorization.getVerificationUri();
		return isBlank(uri) ? null : uri;
	}

	private static void browseWithDesktop(URI uri) throws IOException {
		if (!Desktop.isDesktopSupported()) {
			throw new IOException("Desktop browse is not supported");
		}
		Desktop desktop = Desktop.getDesktop();
		if (!desktop.isSupported(Desktop.Action.BROWSE)) {
			throw new IOException("Desktop browse is not supported");
		}
		try {
			desktop.browse(uri);
		}
		catch (IOException e) {
			throw e;
		}
		catch (RuntimeException e) {
			throw new IOException("Desktop browse is not supported", e);
		}
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}

	@FunctionalInterface
	interface BrowserOpener {
		void browse(URI uri) throws IOException;
	}
}
