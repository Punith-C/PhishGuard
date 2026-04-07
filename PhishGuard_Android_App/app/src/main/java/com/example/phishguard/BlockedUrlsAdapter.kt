package com.example.phishguard

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip

class BlockedUrlsAdapter(
    private val onAllowTemp      : (domain: String) -> Unit,
    private val onAllowPermanent : (domain: String) -> Unit,
    private val onRevoke         : (domain: String) -> Unit
) : ListAdapter<BlockedUrlItem, BlockedUrlsAdapter.ViewHolder>(DIFF) {

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {

        val tvDomain     : TextView       = view.findViewById(R.id.tvDomain)
        val tvExtraInfo  : TextView       = view.findViewById(R.id.tvExtraInfo)
        val chipStatus   : Chip           = view.findViewById(R.id.chipStatus)
        val btnAllow5Min : MaterialButton = view.findViewById(R.id.btnAllow5Min)
        val btnPermanent : MaterialButton = view.findViewById(R.id.btnPermanent)
        val btnRevoke    : MaterialButton = view.findViewById(R.id.btnRevoke)

        fun bind(item: BlockedUrlItem) {
            val ctx = itemView.context

            tvDomain.text    = item.domain
            tvExtraInfo.text = item.extraInfo.ifBlank { "—" }

            // ── Chip style per type ──────────────────────────────────────────
            when (item.itemType) {
                BlockedUrlItem.TYPE_BLOCKED -> {
                    chipStatus.text = "Blocked"
                    chipStatus.setTextColor(ctx.getColor(R.color.danger))
                    chipStatus.chipBackgroundColor = ctx.getColorStateList(R.color.danger_bg)
                    chipStatus.chipStrokeColor     = ctx.getColorStateList(R.color.danger)
                }
                BlockedUrlItem.TYPE_TEMP -> {
                    chipStatus.text = "Allowed (temp)"
                    chipStatus.setTextColor(ctx.getColor(R.color.cyan_primary))
                    chipStatus.chipBackgroundColor = ctx.getColorStateList(R.color.bg_surface_2)
                    chipStatus.chipStrokeColor     = ctx.getColorStateList(R.color.cyan_primary)
                }
                BlockedUrlItem.TYPE_PERMANENT -> {
                    chipStatus.text = "Always Allowed"
                    chipStatus.setTextColor(ctx.getColor(R.color.success))
                    chipStatus.chipBackgroundColor = ctx.getColorStateList(R.color.bg_surface_2)
                    chipStatus.chipStrokeColor     = ctx.getColorStateList(R.color.success)
                }
            }

            // ── Button visibility ────────────────────────────────────────────
            val notPermanent = item.itemType != BlockedUrlItem.TYPE_PERMANENT
            btnAllow5Min.visibility = if (notPermanent) View.VISIBLE else View.GONE
            btnPermanent.visibility = if (notPermanent) View.VISIBLE else View.GONE

            // ── Clicks — pass domain string, matching activity lambdas ───────
            btnAllow5Min.setOnClickListener { onAllowTemp(item.domain) }
            btnPermanent.setOnClickListener { onAllowPermanent(item.domain) }
            btnRevoke.setOnClickListener    { onRevoke(item.domain) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_blocked_url, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<BlockedUrlItem>() {
            override fun areItemsTheSame(
                oldItem: BlockedUrlItem,
                newItem: BlockedUrlItem
            ): Boolean = oldItem.domain == newItem.domain

            override fun areContentsTheSame(
                oldItem: BlockedUrlItem,
                newItem: BlockedUrlItem
            ): Boolean = oldItem == newItem
        }
    }
}