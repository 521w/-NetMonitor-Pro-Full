package com.netmonitor.pro.ui

import com.netmonitor.pro.core.NetEvent

import android.content.*
import android.graphics.*
import android.view.*

class FlowGraphView(context: Context): View(context){

    var events: List<NetEvent> = emptyList()

    override fun onDraw(c: Canvas){
        val p = Paint()
        var y = 80f

        events.takeLast(30).forEach {
            c.drawText("${it.uid} -> ${it.dst}",50f,y,p)
            y+=40f
        }
    }
}
