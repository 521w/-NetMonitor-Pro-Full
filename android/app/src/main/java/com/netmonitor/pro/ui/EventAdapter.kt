package com.netmonitor.pro.ui

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.netmonitor.pro.R
import com.netmonitor.pro.core.NetEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class EventAdapter : RecyclerView.Adapter<EventAdapter.VH>() {
    private val events = mutableListOf<NetEvent>()

    fun addEvent(event: NetEvent) {
        events.add(0, event)
        if (events.size > 50) events.removeAt(events.size - 1)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        return VH(LayoutInflater.from(parent.context).inflate(R.layout.item_event, parent, false))
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = events[position]
        holder.dest.text = "${'$'}{e.destIp}:${'$'}{e.port}"
        holder.details.text = "${'$'}{e.protocol} ${'$'}{e.direction} via ${'$'}{e.appName}"
        val bytes = e.bytesTransferred
        holder.bytes.text = when {
            bytes > 1_000_000 -> "${'$'}{bytes / 1_000_000} MB"
            bytes > 1_000 -> "${'$'}{bytes / 1_000} KB"
            else -> "${'$'}bytes B"
        }
        holder.time.text = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(e.timestamp))
        val dot = GradientDrawable()
        dot.shape = GradientDrawable.OVAL
        dot.setColor(when {
            e.riskLevel > 60 -> Color.parseColor("#F44336")
            e.riskLevel > 30 -> Color.parseColor("#FF9800")
            else -> Color.parseColor("#4CAF50")
        })
        holder.riskDot.background = dot
    }

    override fun getItemCount() = events.size

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val dest: TextView = v.findViewById(R.id.tvEventDest)
        val details: TextView = v.findViewById(R.id.tvEventDetails)
        val bytes: TextView = v.findViewById(R.id.tvEventBytes)
        val time: TextView = v.findViewById(R.id.tvEventTime)
        val riskDot: View = v.findViewById(R.id.viewRiskDot)
    }
}
