package com.netmonitor.pro.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Shader
import android.util.AttributeSet
import android.view.View

class FlowGraphView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : View(context, attrs) {
    private val dataPoints = mutableListOf<Float>()
    private val maxPoints = 40

    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#4FC3F7"); strokeWidth = 3f; style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND; strokeJoin = Paint.Join.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#1A4FC3F7"); strokeWidth = 1f
    }
    private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#0D1B2A")
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#4FC3F7"); textSize = 30f; textAlign = Paint.Align.CENTER
    }
    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#4FC3F7"); style = Paint.Style.FILL
    }

    fun addPoint(value: Float) {
        dataPoints.add(value)
        if (dataPoints.size > maxPoints) dataPoints.removeAt(0)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat(); val h = height.toFloat(); val pad = 16f
        canvas.drawRoundRect(RectF(0f, 0f, w, h), 16f, 16f, bgPaint)
        for (i in 1..4) {
            val y = pad + (h - 2 * pad) * i / 5
            canvas.drawLine(pad, y, w - pad, y, gridPaint)
        }
        if (dataPoints.size < 2) {
            canvas.drawText("\u7b49\u5f85\u6570\u636e...", w / 2, h / 2, textPaint)
            return
        }
        val maxVal = dataPoints.max().coerceAtLeast(1f)
        val stepX = (w - 2 * pad) / (maxPoints - 1)
        val off = maxPoints - dataPoints.size
        val lp = Path(); val fp = Path()
        var lastX = 0f; var lastY = 0f
        for (i in dataPoints.indices) {
            val x = pad + (off + i) * stepX
            val y = h - pad - (dataPoints[i] / maxVal) * (h - 2 * pad)
            if (i == 0) {
                lp.moveTo(x, y); fp.moveTo(x, h - pad); fp.lineTo(x, y)
            } else {
                val cx = (lastX + x) / 2
                lp.cubicTo(cx, lastY, cx, y, x, y)
                fp.cubicTo(cx, lastY, cx, y, x, y)
            }
            lastX = x; lastY = y
        }
        fp.lineTo(lastX, h - pad); fp.close()
        fillPaint.shader = LinearGradient(0f, pad, 0f, h - pad,
            Color.parseColor("#664FC3F7"), Color.parseColor("#004FC3F7"), Shader.TileMode.CLAMP)
        canvas.drawPath(fp, fillPaint)
        canvas.drawPath(lp, linePaint)
        canvas.drawCircle(lastX, lastY, 6f, dotPaint)
    }
}
