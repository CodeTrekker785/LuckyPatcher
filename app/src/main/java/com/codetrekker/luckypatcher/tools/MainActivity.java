package com.codetrekker.luckypatcher.tools;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.graphics.Typeface;
import android.graphics.Color;
import android.view.Gravity;
import android.util.TypedValue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class MainActivity extends Activity {
    private static final int PICK_STATUS = 101, PICK_INSPECT = 102, PICK_COMPARE_A = 103, PICK_COMPARE_B = 104;
    private TextView output;
    private byte[] firstCompare;
    private String firstCompareName;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(15, 19, 26));
        getWindow().setNavigationBarColor(Color.rgb(15, 19, 26));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(22), dp(18), dp(18));
        root.setBackgroundColor(Color.rgb(15, 19, 26));

        TextView title = new TextView(this);
        title.setText("Native Library Inspector");
        title.setTextColor(Color.rgb(236, 243, 250));
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Read-only tools for libpairipcore.so\nInspect ELF details, compare files, or check APK contents.");
        subtitle.setTextColor(Color.rgb(175, 188, 204));
        subtitle.setTextSize(14);
        subtitle.setPadding(0, dp(8), 0, dp(16));
        root.addView(subtitle);

        addButton(root, "Check APK / APKS / XAPK", v -> pick(PICK_STATUS, "application/zip"));
        addButton(root, "Inspect .so library", v -> pick(PICK_INSPECT, "*/*"));
        addButton(root, "Compare two .so files", v -> { firstCompare = null; pick(PICK_COMPARE_A, "*/*"); });

        TextView resultLabel = new TextView(this);
        resultLabel.setText("RESULTS");
        resultLabel.setTextColor(Color.rgb(185, 243, 208));
        resultLabel.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        resultLabel.setPadding(0, dp(16), 0, dp(8));
        root.addView(resultLabel);

        output = new TextView(this);
        output.setText("Choose a tool above to begin.");
        output.setTextColor(Color.rgb(225, 232, 241));
        output.setTextSize(13);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextIsSelectable(true);
        output.setPadding(dp(12), dp(12), dp(12), dp(12));
        output.setBackgroundColor(Color.rgb(25, 31, 41));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        TextView foot = new TextView(this);
        foot.setText("This app never modifies selected files or disables protection/licence checks.");
        foot.setTextColor(Color.rgb(145, 157, 174));
        foot.setTextSize(11);
        foot.setPadding(0, dp(12), 0, 0);
        root.addView(foot);
        setContentView(root);
    }

    private int dp(int value) { return (int)(value * getResources().getDisplayMetrics().density + 0.5f); }

    private void addButton(LinearLayout root, String label, View.OnClickListener listener) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(Color.rgb(12, 35, 24));
        b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(Color.rgb(185, 243, 208)));
        b.setOnClickListener(listener);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(8);
        root.addView(b, lp);
    }

    private void pick(int code, String mime) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        if (code == PICK_STATUS) i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/vnd.android.package-archive", "application/zip", "application/octet-stream"});
        startActivityForResult(i, code);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        String name = uri.getLastPathSegment() == null ? "selected file" : uri.getLastPathSegment();
        try {
            byte[] bytes = readAll(getContentResolver().openInputStream(uri));
            if (request == PICK_STATUS) output.setText(checkArchive(bytes, name));
            else if (request == PICK_INSPECT) output.setText(inspect(bytes, name));
            else if (request == PICK_COMPARE_A) {
                firstCompare = bytes; firstCompareName = name;
                pick(PICK_COMPARE_B, "*/*");
            } else if (request == PICK_COMPARE_B) {
                if (firstCompare == null) { output.setText("Choose the first file again."); return; }
                output.setText(compare(firstCompare, firstCompareName, bytes, name));
                firstCompare = null;
            }
        } catch (Exception e) {
            output.setText("Could not read selected file: " + e.getMessage());
        }
    }

    private byte[] readAll(InputStream in) throws Exception {
        if (in == null) throw new Exception("No readable stream returned.");
        try (InputStream source = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192]; int n; long total = 0;
            while ((n = source.read(buf)) != -1) {
                total += n;
                if (total > 200L * 1024 * 1024) throw new Exception("File exceeds 200 MiB safety limit.");
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private String sha(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder b = new StringBuilder();
        for (byte v : digest) b.append(String.format(Locale.US, "%02x", v & 255));
        return b.toString();
    }

    private String inspect(byte[] data, String name) throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("File: ").append(name).append("\nSize: ").append(data.length).append(" bytes\nSHA-256: ").append(sha(data)).append("\n");
        if (data.length >= 20 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            int cls = data[4] & 255, endian = data[5] & 255;
            int machine = 0;
            if (endian == 1) machine = (data[18] & 255) | ((data[19] & 255) << 8);
            else if (endian == 2) machine = ((data[18] & 255) << 8) | (data[19] & 255);
            String arch = machine == 40 ? "ARM" : machine == 183 ? "AArch64" : machine == 3 ? "x86" : machine == 62 ? "x86-64" : "machine " + machine;
            out.append("ELF: ").append(cls == 1 ? "ELF32" : cls == 2 ? "ELF64" : "unknown class").append("; ").append(arch).append("; ").append(endian == 1 ? "little-endian" : endian == 2 ? "big-endian" : "unknown byte order").append("\n");
        } else out.append("ELF: not recognised as an ELF binary.\n");
        out.append("\nPrintable strings (up to 80):\n");
        int shown = 0, start = -1;
        for (int i = 0; i <= data.length && shown < 80; i++) {
            boolean printable = i < data.length && (data[i] & 255) >= 32 && (data[i] & 255) <= 126;
            if (printable && start < 0) start = i;
            if ((!printable || i == data.length) && start >= 0) {
                if (i - start >= 4) {
                    out.append("  ").append(new String(data, start, Math.min(i - start, 240), java.nio.charset.StandardCharsets.US_ASCII)).append("\n");
                    shown++;
                }
                start = -1;
            }
        }
        out.append("\nExported symbols are not decoded by this lightweight APK. Use the Termux tool with readelf for symbol tables.\nRead-only: no bytes changed.");
        return out.toString();
    }

    private String compare(byte[] a, String an, byte[] b, String bn) throws Exception {
        boolean same = java.util.Arrays.equals(a, b);
        return "A: " + an + "\nSize: " + a.length + "\nSHA-256: " + sha(a) +
                "\n\nB: " + bn + "\nSize: " + b.length + "\nSHA-256: " + sha(b) +
                "\n\nResult: " + (same ? "IDENTICAL" : "DIFFERENT") + "\nComparison is read-only; neither file was changed.";
    }

    private String checkArchive(byte[] data, String name) {
        ArrayList<String> found = new ArrayList<>();
        scanZip(data, name, 0, found);
        if (found.isEmpty()) return "NOT FOUND: libpairipcore.so was not found in the scanned archive.\nThis does not rule out runtime downloads or renamed/packed libraries.";
        StringBuilder b = new StringBuilder("FOUND libpairipcore.so (").append(found.size()).append(" entr").append(found.size() == 1 ? "y" : "ies").append("):\n");
        for (String s : found) b.append("  ").append(s).append("\n");
        b.append("Presence does not prove the library is loaded or active at runtime.");
        return b.toString();
    }

    private byte[] readEntryBytes(ZipInputStream zin) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = zin.read(buffer)) != -1) {
            if (out.size() + n > 200 * 1024 * 1024) throw new Exception("Nested archive too large");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private void scanZip(byte[] data, String label, int depth, ArrayList<String> found) {
        if (depth > 6) return;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                String n = entry.getName();
                if (n.substring(n.lastIndexOf('/') + 1).equalsIgnoreCase("libpairipcore.so")) {
                    found.add(label + "!/" + n);
                } else if (!entry.isDirectory() && (n.toLowerCase(Locale.ROOT).endsWith(".apk") || n.toLowerCase(Locale.ROOT).endsWith(".zip") || n.toLowerCase(Locale.ROOT).endsWith(".apks") || n.toLowerCase(Locale.ROOT).endsWith(".xapk"))) {
                    try {
                        byte[] nested = readEntryBytes(zin);
                        scanZip(nested, label + "!/" + n, depth + 1, found);
                    } catch (Exception ignored) { }
                }
                zin.closeEntry();
            }
        } catch (Exception ignored) { }
    }
}
