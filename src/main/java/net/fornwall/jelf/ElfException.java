package net.fornwall.jelf;

/**
 * Generic exception class for all exceptions which occur in this package. Since
 * there is no mechanism built into this library for recovering from errors, the
 * best clients can do is display the error string.
 */
public class ElfException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ElfException(String message) {
		super(message);
	}

	public ElfException(Throwable cause) {
		super(cause);
	}

	public ElfException(String message, Throwable cause) {
		super(message, cause);
	}

}
