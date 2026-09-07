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
package ghidra.framework.remote;

import static org.junit.Assert.*;

import java.io.*;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;

public class GhidraObjectInputFilterTest extends AbstractGenericTest {

	private GhidraObjectInputFilter filter;

	public GhidraObjectInputFilterTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		File temp = createTempDirectory("serial-filter");
		File dataDir = new File(temp, "data");
		assertTrue(dataDir.mkdirs());
		File filterFile = new File(dataDir, "test.serial.filter");
		try (FileWriter w = new FileWriter(filterFile)) {
			w.write("ghidra.framework.remote.FidoAuthenticationCallback;\n");
		}
		filter = new GhidraObjectInputFilter();
		filter.initializeFilter(List.of(new ResourceFile(filterFile)), null);
	}

	@Test
	public void testPrimitiveArrayAllowList() {
		assertEquals(ObjectInputFilter.Status.ALLOWED, filter.checkInput(info(byte[].class, 4)));
		assertEquals(ObjectInputFilter.Status.ALLOWED, filter.checkInput(info(byte[][].class, 2)));
		assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(info(int[][].class, 2)));
		assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(info(byte[][][].class, 1)));
		assertEquals(ObjectInputFilter.Status.REJECTED, filter.checkInput(info(String[].class, 1)));
		assertEquals(ObjectInputFilter.Status.REJECTED,
			filter.checkInput(info(Object[][].class, 1)));
	}

	@Test
	public void testFidoCallbackWithAllowCredentialsDeserializes() throws Exception {
		byte[] challenge = bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
			20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
		byte[] credId = bytes(0xAA, 0xBB, 0xCC);
		FidoAuthenticationCallback original = new FidoAuthenticationCallback("ghidra.example.org",
			"Example", challenge, new byte[][] { credId }, false, 60);

		FidoAuthenticationCallback copy =
			(FidoAuthenticationCallback) roundTripWithFilter(original);

		assertEquals("ghidra.example.org", copy.getRpId());
		assertEquals(1, copy.getAllowCredentials().length);
		assertArrayEquals(credId, copy.getAllowCredentials()[0]);
	}

	@Test
	public void testByteArrayRoundTripAllowed() throws Exception {
		byte[] payload = bytes(1, 2, 3, 4);
		assertArrayEquals(payload, (byte[]) roundTripWithFilter(payload));
		byte[][] rows = new byte[][] { payload };
		byte[][] copy = (byte[][]) roundTripWithFilter(rows);
		assertEquals(1, copy.length);
		assertArrayEquals(payload, copy[0]);
	}

	@Test
	public void testUnlistedArraysRejected() throws Exception {
		assertRejected(new String[] { "x" });
		assertRejected(new Object[][] { { "x" } });
		assertRejected(new int[][] { { 1, 2 } });
	}

	private void assertRejected(Object obj) throws Exception {
		try {
			roundTripWithFilter(obj);
			fail("expected InvalidClassException for " + obj.getClass().getName());
		}
		catch (InvalidClassException e) {
			// expected
		}
	}

	private Object roundTripWithFilter(Object obj) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
			oos.writeObject(obj);
		}
		try (ObjectInputStream ois =
			new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
			ois.setObjectInputFilter(filter);
			return ois.readObject();
		}
	}

	private static ObjectInputFilter.FilterInfo info(Class<?> serialClass, long arrayLength) {
		return new ObjectInputFilter.FilterInfo() {
			@Override
			public Class<?> serialClass() {
				return serialClass;
			}

			@Override
			public long arrayLength() {
				return arrayLength;
			}

			@Override
			public long depth() {
				return 1;
			}

			@Override
			public long references() {
				return 1;
			}

			@Override
			public long streamBytes() {
				return 1;
			}
		};
	}

}
