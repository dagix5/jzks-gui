package it.unisa.dia.jzks.gui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI
 * Builder, which is free for non-commercial use. If Jigloo is being used
 * commercially (ie, by a corporation, company or business for any purpose
 * whatever) then you should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details. Use of Jigloo implies
 * acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN
 * PURCHASED FOR THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR
 * ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class Main_JZKS extends javax.swing.JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JLabel imageIntro;
	private static Main_JZKS inst;

	/**
	 * Auto-generated main method to display this JFrame
	 */
	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				inst = new Main_JZKS();
				inst.setLocationRelativeTo(null);

				Timer timer = new Timer(1500, new ActionListener() {

					public void actionPerformed(ActionEvent e) {
						Operating oper = new Operating();
						inst.setVisible(false);
						oper.setLocationRelativeTo(null);
						oper.setVisible(true);
						inst.dispose();

					}
				});
				timer.start();
				timer.setRepeats(false);
			}
		});
	}

	public Main_JZKS() {
		super();
		initGUI();
	}

	private void initGUI() {
		try {
			{
				this.setTitle("Java Zero-Knowledge Sets");
				this.setResizable(false);
				this.setUndecorated(true);
				this.rootPane.setWindowDecorationStyle(JRootPane.NONE);
				this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
				{
					imageIntro = new JLabel();
					getContentPane().add(imageIntro, BorderLayout.CENTER);
					imageIntro.setText("imageIntro");
					imageIntro.setIcon(new ImageIcon(getClass()
							.getClassLoader().getResource(
									"img/sciam_cryptography_final.jpg")));
					imageIntro
							.setPreferredSize(new java.awt.Dimension(480, 622));
				}
				this.setVisible(true);
			}
			pack();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
