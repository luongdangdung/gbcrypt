package org.streetjava.util;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

/**
 *
 * @author dungld
 */
public class SJUtil {

    public static String getStacktrace() {
        StringBuilder result = new StringBuilder();

        StackTraceElement[] stackTraceArr = getStackTraceArr();

        for (StackTraceElement element : stackTraceArr) {
            result.append("\t at ");
            result.append(element);
            result.append("\n");
        }

        return result.toString();
    }

    public static String getStacktrace(int line) {
        if (line <= 0) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        StackTraceElement[] stackTraceArr = getStackTraceArr();

        int count = 1;

        for (StackTraceElement element : stackTraceArr) {
            result.append("\t at ");
            result.append(element);
            result.append("\n");

            if (count == line) {
                break;
            }

            count++;
        }

        return result.toString();

    }

    public static String GET_STACKTRACE(Throwable t) {
        Writer result = new StringWriter();
        t.printStackTrace(new PrintWriter(result));
        return result.toString();
    }

    private static StackTraceElement[] getStackTraceArr() {
        return Thread.currentThread().getStackTrace();
    }
}
