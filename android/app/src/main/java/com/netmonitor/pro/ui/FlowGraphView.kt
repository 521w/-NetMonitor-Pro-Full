package com.netmonitor.pro.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.util.AttributeSet
import android.view.View

class FlowGraphView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : View(context, attrs) {

    private val dataPoints = mutableListOf<Float>()
    private val maxPoints = 30
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#1976D2"); strokeWidth = 4f; style = Paint.Style.STROKE
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#E0E0E0"); strokeWidth = 1f
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#9E9E9E"); textSize = 28f
    }

    fun addPoint(value: Float) {
        dataPoints.add(value)
        if (dataPoints.size > maxPoints) dataPoints.removeAt(0)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat(); val h = height.toFloat(); val pad = 20f
        for (i in 1..3) { val y = pad + (h - 2*pad)*i/4; canvas.drawLine(pad, y, w-pad, y, gridPaint) }
        if (dataPoints.size < 2) { canvas.drawText("Waiting for data...", w/2-100, h/2, textPaint); return }
        val maxVal = dataPoints.max().coerceAtLeast(1f)
        val stepX = (w - 2*pad) / (maxPoints - 1)
        val off = maxPoints - dataPoints.size
        val lp = Path(); val fp = Path()
        for (i in dataPoints.indices) {
            val x = pad + (off+i)*stepX; val y = h - pad - (dataPoints[i]/maxVal)*(h-2*pad)
            if (i==0) { lp.moveTo(x,y); fp.moveTo(x,h-pad); fp.lineTo(x,y) } else { lp.lineTo(x,y); fp.lineTo(x,y) }
        }
        fp.lineTo(pad+(off+dataPoints.size-1)*stepX, h-pad); fp.close()
        fillPaint.shader = LinearGradient(0f, pad, 0f, h-pad, Color.parseColor("#401976D2"), Color.parseColor("#001976D2"), Shader.TileMode.CLAMP)
        canvas.drawPath(fp, fillPaint); canvas.drawPath(lp, linePaint)
    }
}
