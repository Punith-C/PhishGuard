package com.example.phishguard

import android.content.Intent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip

class BlockedDomainAdapter(
    private val onAllowClicked: (BlockedDomainEntry) -> Unit,
    private val onBlockClicked: (BlockedDomainEntry) -> Unit
) : RecyclerView.Adapter<BlockedDomainAdapter.DomainViewHolder>() {

    private var domains: List<BlockedDomainEntry> = emptyList()

    fun submitList(list: List<BlockedDomainEntry>?) {
        domains = list ?: emptyList()
        notifyDataSetChanged()
    }

    class DomainViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvDomain: TextView = view.findViewById(R.id.tvDomain)
        val chipStatus: Chip = view.findViewById(R.id.chipStatus)
        val tvTimeAgo: TextView = view.findViewById(R.id.tvTimeAgo)
        val tvCount: TextView = view.findViewById(R.id.tvCount)
        val btnAllow: MaterialButton = view.findViewById(R.id.btnAllow)
        val btnBlock: MaterialButton = view.findViewById(R.id.btnBlock)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DomainViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_blocked_domain, parent, false)
        return DomainViewHolder(view)
    }

    override fun onBindViewHolder(holder: DomainViewHolder, position: Int) {
        val entry = domains[position]

        holder.tvDomain.text = entry.domain
        holder.tvCount.text = "${entry.count}x blocked"
        holder.tvTimeAgo.text = "Just now"

        val context = holder.itemView.context

        if (entry.allowed) {
            holder.chipStatus.text = "Allowed"
            holder.chipStatus.setChipBackgroundColorResource(R.color.success_bg)

            holder.btnAllow.visibility = View.GONE
            holder.btnBlock.visibility = View.VISIBLE

            holder.btnBlock.setOnClickListener {
                onBlockClicked(entry)

                val intent = Intent("com.example.phishguard.DOMAIN_BLOCKED")
                intent.setPackage(context.packageName)
                intent.putExtra("domain", entry.domain)

                context.sendBroadcast(intent)
            }
        } else {
            holder.chipStatus.text = "Blocked"
            holder.chipStatus.setChipBackgroundColorResource(R.color.danger_bg)

            holder.btnAllow.visibility = View.VISIBLE
            holder.btnBlock.visibility = View.GONE

            holder.btnAllow.setOnClickListener {
                onAllowClicked(entry)
            }
        }
    }

    override fun getItemCount(): Int = domains.size
}