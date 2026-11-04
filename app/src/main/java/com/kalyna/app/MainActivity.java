package com.kalyna.app;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.webkit.MimeTypeMap;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final int REQ_IN = 1;
    private static final int REQ_OUT = 2;

    private RadioButton rbEnc, rbDec;
    private TextView tvFile, tvStatus;
    private EditText etPw, etPw2;
    private Button btnPick, btnRun;
    private ProgressBar bar;

    private Uri inUri;
    private String inName;
    private long inSize = -1;
    private boolean working = false;

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(24), dp(20), dp(24));
        sv.addView(root);

        TextView title = new TextView(this);
        title.setText("Kalyna-512 KGCM");
        title.setTextSize(24);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("Cifrado de archivos por contraseña (DSTU 7624:2014)");
        sub.setPadding(0, dp(4), 0, dp(16));
        root.addView(sub);

        RadioGroup rg = new RadioGroup(this);
        rg.setOrientation(RadioGroup.HORIZONTAL);
        rbEnc = new RadioButton(this);
        rbEnc.setText("Cifrar");
        rbEnc.setId(View.generateViewId());
        rbDec = new RadioButton(this);
        rbDec.setText("Descifrar");
        rbDec.setId(View.generateViewId());
        rg.addView(rbEnc);
        rg.addView(rbDec);
        rbEnc.setChecked(true);
        root.addView(rg);

        btnPick = new Button(this);
        btnPick.setText("Elegir archivo");
        btnPick.setOnClickListener(v -> pickFile());
        root.addView(btnPick);

        tvFile = new TextView(this);
        tvFile.setText("Ningún archivo seleccionado");
        tvFile.setPadding(0, dp(4), 0, dp(12));
        root.addView(tvFile);

        etPw = new EditText(this);
        etPw.setHint("Contraseña");
        etPw.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        root.addView(etPw);

        etPw2 = new EditText(this);
        etPw2.setHint("Repite la contraseña");
        etPw2.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        root.addView(etPw2);

        rg.setOnCheckedChangeListener((g, id) ->
                etPw2.setVisibility(rbEnc.isChecked() ? View.VISIBLE : View.GONE));

        btnRun = new Button(this);
        btnRun.setText("Ejecutar");
        btnRun.setOnClickListener(v -> onRun());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(16);
        root.addView(btnRun, lp);

        bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(1000);
        bar.setVisibility(View.GONE);
        LinearLayout.LayoutParams lpb = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lpb.topMargin = dp(16);
        root.addView(bar, lpb);

        tvStatus = new TextView(this);
        tvStatus.setPadding(0, dp(8), 0, 0);
        root.addView(tvStatus);

        setContentView(sv);
    }

    private void pickFile() {
        if (working) return;
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, REQ_IN);
    }

    private void onRun() {
        if (working) return;
        if (inUri == null) {
            toast("Elige primero un archivo");
            return;
        }
        int n = etPw.getText().length();
        if (n == 0) {
            toast("Escribe la contraseña");
            return;
        }
        boolean enc = rbEnc.isChecked();
        if (enc && !etPw.getText().toString().equals(etPw2.getText().toString())) {
            toast("Las contraseñas no coinciden");
            return;
        }
        if (enc && n < 8) {
            toast("Usa una contraseña de al menos 8 caracteres");
            return;
        }

        String outName;
        if (enc) {
            outName = inName + ".enc";
        } else if (inName.toLowerCase(Locale.ROOT).endsWith(".enc") && inName.length() > 4) {
            outName = inName.substring(0, inName.length() - 4);
        } else {
            outName = inName + ".dec";
        }

        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mimeFor(outName));
        i.putExtra(Intent.EXTRA_TITLE, outName);
        startActivityForResult(i, REQ_OUT);
    }

    private String mimeFor(String name) {
        int dot = name.lastIndexOf('.');
        if (dot >= 0 && dot < name.length() - 1) {
            String ext = name.substring(dot + 1).toLowerCase(Locale.ROOT);
            String m = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext);
            if (m != null) return m;
        }
        return "application/octet-stream";
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (req == REQ_IN) {
            inUri = uri;
            inName = "archivo";
            inSize = -1;
            Cursor c = null;
            try {
                c = getContentResolver().query(uri, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    int ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    int si = c.getColumnIndex(OpenableColumns.SIZE);
                    if (ni >= 0 && !c.isNull(ni)) inName = c.getString(ni);
                    if (si >= 0 && !c.isNull(si)) inSize = c.getLong(si);
                }
            } catch (Exception ignored) {
            } finally {
                if (c != null) c.close();
            }
            tvFile.setText(inName + (inSize >= 0 ? "  (" + human(inSize) + ")" : ""));
            tvStatus.setText("");
        } else if (req == REQ_OUT) {
            start(uri);
        }
    }

    private String human(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.ROOT, "%.1f MB", b / 1048576.0);
        return String.format(Locale.ROOT, "%.2f GB", b / 1073741824.0);
    }

    private void start(final Uri outUri) {
        final boolean enc = rbEnc.isChecked();
        final Uri src = inUri;
        final long total = inSize;
        final char[] pw = new char[etPw.getText().length()];
        etPw.getText().getChars(0, pw.length, pw, 0);

        setBusy(true);
        tvStatus.setText(enc ? "Cifrando… (derivando clave)" : "Descifrando… (derivando clave)");
        bar.setIndeterminate(true);

        new Thread(() -> {
            String err = null;
            try (InputStream in = new BufferedInputStream(
                         getContentResolver().openInputStream(src), 1 << 16);
                 OutputStream out = new BufferedOutputStream(
                         getContentResolver().openOutputStream(outUri, "w"), 1 << 16)) {
                KalynaCrypto.Progress p = done -> runOnUiThread(() -> {
                    if (total > 0) {
                        bar.setIndeterminate(false);
                        bar.setProgress((int) Math.min(1000, done * 1000 / total));
                    }
                });
                if (enc) KalynaCrypto.encrypt(in, out, pw, p);
                else KalynaCrypto.decrypt(in, out, pw, p);
            } catch (Throwable t) {
                String m = t.getMessage();
                err = (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
            } finally {
                Arrays.fill(pw, '\0');
            }
            if (err != null) {
                try {
                    DocumentsContract.deleteDocument(getContentResolver(), outUri);
                } catch (Exception ignored) {
                }
            }
            final String e = err;
            runOnUiThread(() -> finishWork(e, enc));
        }).start();
    }

    private void finishWork(String err, boolean enc) {
        setBusy(false);
        bar.setIndeterminate(false);
        if (err == null) {
            bar.setProgress(1000);
            tvStatus.setText(enc ? "Listo: archivo cifrado guardado." : "Listo: archivo descifrado guardado.");
            etPw.setText("");
            etPw2.setText("");
        } else {
            bar.setProgress(0);
            tvStatus.setText("Error: " + err);
        }
    }

    private void setBusy(boolean b) {
        working = b;
        btnPick.setEnabled(!b);
        btnRun.setEnabled(!b);
        rbEnc.setEnabled(!b);
        rbDec.setEnabled(!b);
        bar.setVisibility(b || bar.getProgress() > 0 ? View.VISIBLE : View.GONE);
        if (b) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
