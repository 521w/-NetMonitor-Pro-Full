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
        if (events.size > 100) events.removeAt(events.size - 1)
        notifyItemInserted(0)
    }

    fun setEvents(list: List<NetEvent>) {
        events.clear()
        events.addAll(list)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        return VH(LayoutInflater.from(parent.context).inflate(R.layout.item_event, parent, false))
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = events[position]
        holder.app.text = e.appName.ifEmpty { e.packageName.substringAfterLast('.') }
        holder.dest.text = if (e.destHost.isNotEmpty()) e.destHost else if (e.destIp.isNotEmpty()) "${e.destIp}:${e.port}" else "\u672c\u5730\u6d41\u91cf"
        val total = e.txBytes + e.rxBytes
        holder.bytes.text = when {
            total > 1_000_000 -> "${total / 1_000_000} MB"
            total > 1_000 -> "${total / 1_000} KB"
            else -> "$total B"
        }
        holder.dir.text = if (e.direction == "OUT") "\u2191" else "\u2193"
        holder.dir.setTextColor(if (e.direction == "OUT") Color.parseColor("#FF7043") else Color.parseColor("#66BB6A"))
        holder.time.text = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(e.timestamp))
        val dot = GradientDrawable()
        dot.shape = GradientDrawable.OVAL
        dot.setSize(24, 24)
        dot.setColor(when {
            e.riskLevel > 60 -> Color.parseColor("#F44336")
            e.riskLevel > 30 -> Color.parseColor("#FF9800")
            else -> Color.parseColor("#4CAF50")
        })
        holder.riskDot.background = dot
    }

    override fun getItemCount() = events.size

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val app: TextView = v.findViewById(R.id.tvApp)
        val dest: TextView = v.findViewById(R.id.tvDest)
        val bytes: TextView = v.findViewById(R.id.tvBytes)
        val dir: TextView = v.findViewById(R.id.tvDir)
        val time: TextView = v.findViewById(R.id.tvTime)
        val riskDot: View = v.findViewById(R.id.dotRisk)
    }
}
