package net.fornwall.jelf;

import java.io.IOException;

/**
 * A memoized object. Override {@link #computeValue} in subclasses; call {@link #getValue} in using code.
 */
public abstract class MemoizedObject<T> {
	private boolean computed;
	private T value;

	/**
	 * Should compute the value of this memoized object. This will only be called once, upon the first call to
	 * {@link #getValue}.
	 */
	protected abstract T computeValue() throws ElfException, IOException;

	/** Public accessor for the memoized value. */
	public final T getValue() throws ElfException, IOException {
		if (!computed) {
			value = computeValue();
			computed = true;
		}
		return value;
	}
	
	@SuppressWarnings("unchecked")
	public static <T> MemoizedObject<T>[] uncheckedArray(int size) {
		return new MemoizedObject[size];
	}
}